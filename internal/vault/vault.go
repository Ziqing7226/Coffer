// Package vault implements the on-disk vault format v1, normatively
// specified in docs/format-spec.md: a plaintext vault.meta header with key
// slots, numbered encrypted manifest generations, and immutable chunked
// object files under obj/.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ziqing7226/Coffer/internal/crypto"
)

const (
	metaName               = "vault.meta"
	objDirName             = "obj"
	manifestPrefix         = "manifest."
	defaultGenerationsKept = 2
	objectNameBytes        = 16 // 32 hex chars per spec §5
)

var (
	// ErrNotVault reports a directory that is not a readable coffer vault.
	ErrNotVault = errors.New("not a coffer vault")
	// ErrCorrupt reports vault data that fails structural validation.
	ErrCorrupt = errors.New("vault data corrupted")
)

// Meta is the plaintext vault header (spec §3). It carries everything a
// reader needs before any secret is derived: format version, vault
// identity, and the key slots.
type Meta struct {
	FormatVersion int           `json:"format_version"`
	ID            string        `json:"id"`
	Created       time.Time     `json:"created"`
	Slots         []crypto.Slot `json:"slots"`
}

// RefVal is one advertised ref (spec §4).
type RefVal struct {
	OID    string  `json:"oid"`
	Peeled *string `json:"peeled"`
}

// PackInfo describes one stored object file: the SHA-256 and plaintext size
// of the pack it holds, and the object ids it contains (spec §4).
type PackInfo struct {
	SHA256  string   `json:"sha256"`
	Size    int64    `json:"size"`
	Objects []string `json:"objects"`
}

// Generations bounds how many manifest generations are retained.
type Generations struct {
	Kept int `json:"kept"`
}

// Manifest is the decrypted vault index (spec §4).
type Manifest struct {
	Version     int                 `json:"version"`
	Generated   time.Time           `json:"generated"`
	Prev        *string             `json:"prev"`
	Refs        map[string]RefVal   `json:"refs"`
	Packs       map[string]PackInfo `json:"packs"`
	Generations Generations         `json:"generations"`
}

// NewManifest returns an empty manifest with spec defaults.
func NewManifest() *Manifest {
	return &Manifest{
		Version:     crypto.FormatVersion,
		Refs:        map[string]RefVal{},
		Packs:       map[string]PackInfo{},
		Generations: Generations{Kept: defaultGenerationsKept},
	}
}

// Store is an opened vault. All methods are safe for use by one goroutine;
// the helper process uses a single-threaded conversation loop.
type Store struct {
	dir         string
	meta        Meta
	dek         []byte
	manifest    *Manifest
	manifestNum int
	payloadHash string
}

// Dir returns the vault directory.
func (s *Store) Dir() string { return s.dir }

// Meta returns the plaintext vault header.
func (s *Store) Meta() Meta { return s.meta }

// Manifest returns the current (newest authenticating) manifest. Callers may
// mutate it and pass the same pointer to Commit.
func (s *Store) Manifest() *Manifest { return s.manifest }

// ManifestNum returns the generation number of the current manifest.
func (s *Store) ManifestNum() int { return s.manifestNum }

// ReadMeta reads and validates the plaintext vault header without deriving
// any key.
func ReadMeta(dir string) (Meta, error) {
	data, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		if os.IsNotExist(err) {
			return Meta{}, fmt.Errorf("%w: %s is missing", ErrNotVault, metaName)
		}
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("%w: %s is malformed: %v", ErrNotVault, metaName, err)
	}
	if m.FormatVersion != crypto.FormatVersion {
		return Meta{}, fmt.Errorf("vault format version %d not supported by this build (supports %d)",
			m.FormatVersion, crypto.FormatVersion)
	}
	if m.ID == "" || len(m.Slots) == 0 {
		return Meta{}, fmt.Errorf("%w: %s lacks id or key slots", ErrCorrupt, metaName)
	}
	return m, nil
}

// Create initializes a new vault at dir: one key slot sealed with passphrase,
// and generation 1 holding an empty manifest.
func Create(dir, passphrase string, params crypto.Argon2Params) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, objDirName), 0o700); err != nil {
		return nil, err
	}
	id, err := crypto.RandomHex(16)
	if err != nil {
		return nil, err
	}
	dek, err := crypto.NewDEK()
	if err != nil {
		return nil, err
	}
	slot, err := crypto.SealSlot(0, passphrase, dek, id, params)
	if err != nil {
		return nil, err
	}
	meta := Meta{
		FormatVersion: crypto.FormatVersion,
		ID:            id,
		Created:       time.Now().UTC(),
		Slots:         []crypto.Slot{*slot},
	}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(dir, metaName, func(f *os.File) error {
		_, err := f.Write(metaData)
		return err
	}); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, meta: meta, dek: dek}
	if err := s.commit(NewManifest()); err != nil {
		return nil, err
	}
	return s, nil
}

// Open opens an existing vault: the passphrase must open at least one key
// slot, and the newest manifest generation that authenticates becomes
// current. If the newest generation is damaged, Open falls back to the
// previous one (kept generations per spec §4).
func Open(dir, passphrase string) (*Store, error) {
	meta, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	var dek []byte
	var authErr error
	for i := range meta.Slots {
		dek, authErr = meta.Slots[i].Open(passphrase, meta.ID)
		if authErr == nil {
			break
		}
		dek = nil
	}
	if dek == nil {
		return nil, fmt.Errorf("%w: passphrase rejected by every key slot", authErr)
	}
	s := &Store{dir: dir, meta: meta, dek: dek}
	var lastErr error
	for _, n := range manifestGenerations(dir) {
		m, hash, err := s.readManifestNum(n)
		if err != nil {
			lastErr = err
			continue
		}
		s.manifest, s.manifestNum, s.payloadHash = m, n, hash
		return s, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no manifest generations found")
	}
	return nil, fmt.Errorf("%w: no usable manifest generation (%v)", ErrCorrupt, lastErr)
}

func (s *Store) readManifestNum(n int) (*Manifest, string, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, fmt.Sprintf("%s%d", manifestPrefix, n)))
	if err != nil {
		return nil, "", err
	}
	payload, err := crypto.OpenManifest(s.dek, s.meta.ID, data)
	if err != nil {
		return nil, "", err
	}
	var m Manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, "", fmt.Errorf("%w: manifest %d is malformed: %v", ErrCorrupt, n, err)
	}
	if m.Version != crypto.FormatVersion {
		return nil, "", fmt.Errorf("manifest %d: unsupported version %d", n, m.Version)
	}
	return &m, crypto.Hash(payload), nil
}

// manifestGenerations lists existing manifest generation numbers, newest
// first, ignoring temp files.
func manifestGenerations(dir string) []int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var nums []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, manifestPrefix) || strings.HasSuffix(name, ".tmp") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(name, manifestPrefix)); err == nil {
			nums = append(nums, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	return nums
}

// GenerationNums returns the manifest generation numbers present on disk,
// newest first.
func GenerationNums(dir string) []int { return manifestGenerations(dir) }

// WriteObject encrypts plaintext into a new immutable object file and
// returns its name. Following spec §6, the file is written to a temp name,
// fsynced, renamed, and the directory flushed; it is never modified again.
func (s *Store) WriteObject(plain io.Reader) (string, error) {
	var name string
	for attempt := 0; attempt < 4; attempt++ {
		candidate, err := crypto.RandomHex(objectNameBytes)
		if err != nil {
			return "", err
		}
		if _, statErr := os.Stat(filepath.Join(s.dir, objDirName, candidate)); os.IsNotExist(statErr) {
			name = candidate
			break
		}
	}
	if name == "" {
		return "", errors.New("could not allocate an object file name")
	}
	objPath := filepath.Join(s.dir, objDirName, name)
	tmp := objPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	specific := func(k int) string { return fmt.Sprintf("%s/%s/%d", s.meta.ID, name, k) }
	err = crypto.WriteChunked(f, plain, s.dek, specific)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	crashPoint("after-object-write")
	if err := os.Rename(tmp, objPath); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := syncDir(filepath.Join(s.dir, objDirName)); err != nil {
		return "", err
	}
	crashPoint("after-object-rename")
	return name, nil
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (rc readCloser) Close() error { return rc.c.Close() }

// ReadObject returns a decrypting reader over the object file name, framed
// by the plaintext size recorded in the current manifest. The caller must
// Close the reader.
func (s *Store) ReadObject(name string) (io.ReadCloser, error) {
	info, ok := s.manifest.Packs[name]
	if !ok {
		return nil, fmt.Errorf("object %q is not in the current manifest", name)
	}
	f, err := os.Open(filepath.Join(s.dir, objDirName, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: object file %q is missing", ErrCorrupt, name)
		}
		return nil, err
	}
	specific := func(k int) string { return fmt.Sprintf("%s/%s/%d", s.meta.ID, name, k) }
	r, err := crypto.ReadChunked(f, info.Size, s.dek, specific)
	if err != nil {
		f.Close()
		return nil, err
	}
	return readCloser{Reader: r, c: f}, nil
}

// Commit writes next as a new manifest generation using the write ordering
// of spec §6: seal the payload, write manifest.<n+1>.tmp, fsync, rename,
// flush the directory, then prune generations beyond the kept bound.
func (s *Store) Commit(next *Manifest) error {
	return s.commit(next)
}

func (s *Store) commit(next *Manifest) error {
	if s.manifestNum > 0 {
		prev := s.payloadHash
		next.Prev = &prev
	}
	next.Generated = time.Now().UTC()
	if next.Generations.Kept <= 0 {
		next.Generations.Kept = defaultGenerationsKept
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}
	crashPoint("before-manifest-commit")
	record, err := crypto.SealManifest(s.dek, s.meta.ID, payload)
	if err != nil {
		return err
	}
	newNum := s.manifestNum + 1
	tmp := filepath.Join(s.dir, fmt.Sprintf("%s%d.tmp", manifestPrefix, newNum))
	if err := os.WriteFile(tmp, record, 0o600); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err == nil {
		f.Sync()
		f.Close()
	}
	crashPoint("after-manifest-write")
	final := filepath.Join(s.dir, fmt.Sprintf("%s%d", manifestPrefix, newNum))
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	crashPoint("after-manifest-commit")
	s.pruneGenerations(newNum, next.Generations.Kept)
	s.manifest, s.manifestNum, s.payloadHash = next, newNum, crypto.Hash(payload)
	return nil
}

func (s *Store) pruneGenerations(newest, kept int) {
	for _, n := range manifestGenerations(s.dir) {
		if n >= newest-kept+1 {
			continue
		}
		os.Remove(filepath.Join(s.dir, fmt.Sprintf("%s%d", manifestPrefix, n)))
	}
}
