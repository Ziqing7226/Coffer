// Package crypto implements the cryptographic envelope of vault format v1
// (docs/format-spec.md): Argon2id key derivation, key slots sealing a random
// data-encryption key, and XChaCha20-Poly1305 AEAD with role-binding
// additional authenticated data.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// FormatVersion is the on-disk format version implemented by this package.
const FormatVersion = 1

// Algorithm and size constants per the format specification.
const (
	KDFAlgo     = "argon2id"
	AEADAlgo    = "xchacha20-poly1305"
	DEKSize     = chacha20poly1305.KeySize    // 32
	NonceSize   = chacha20poly1305.NonceSizeX // 24
	TagSize     = chacha20poly1305.Overhead   // 16
	SaltSize    = 16
	MinSaltSize = 8
)

// ErrAuth reports a passphrase or integrity failure: the sealed data did not
// authenticate under the derived key.
var ErrAuth = errors.New("authentication failed (wrong passphrase or tampered data)")

// Argon2Params are the key-derivation parameters stored per key slot.
type Argon2Params struct {
	Algo string `json:"algo"`
	M    uint32 `json:"m"` // memory in KiB
	T    uint32 `json:"t"` // iterations
	P    uint32 `json:"p"` // parallelism
	Salt []byte `json:"salt"`
}

// KDF parameter ceilings: stored parameters come from untrusted media, so
// derivation must refuse absurd values instead of allocating gigabytes or
// panicking inside argon2 (spec §2 allows implementation-defined ceilings).
const (
	MaxMemoryKiB = 4 << 20 // 4 GiB
	MaxTime      = 1 << 10
	MaxParallel  = 255 // must fit the uint8 argon2 takes
)

// DefaultParams returns the recommended Argon2id parameters for new slots
// (64 MiB, 3 iterations, 4 lanes per docs/format-spec.md §2).
func DefaultParams() Argon2Params {
	return Argon2Params{Algo: KDFAlgo, M: 64 * 1024, T: 3, P: 4}
}

func (p Argon2Params) validate() error {
	if p.Algo != KDFAlgo {
		return fmt.Errorf("unsupported kdf %q", p.Algo)
	}
	if p.P < 1 || p.P > MaxParallel {
		return fmt.Errorf("kdf parallelism %d out of bounds", p.P)
	}
	if p.M < 8*p.P || p.M > MaxMemoryKiB {
		return fmt.Errorf("kdf memory %d KiB out of bounds", p.M)
	}
	if p.T < 1 || p.T > MaxTime {
		return fmt.Errorf("kdf time %d out of bounds", p.T)
	}
	// A nil salt is acceptable here: SealSlot generates one. A present salt
	// must meet the minimum length.
	if p.Salt != nil && len(p.Salt) < MinSaltSize {
		return fmt.Errorf("kdf salt too short")
	}
	return nil
}

// AEADInfo names the AEAD algorithm and nonce used for one sealed record.
type AEADInfo struct {
	Algo  string `json:"algo"`
	Nonce []byte `json:"nonce"`
}

// Slot seals the data-encryption key under one passphrase. The sealed DEK
// only opens under the passphrase whose Argon2id derivation matches the
// stored parameters and salt.
type Slot struct {
	ID   int          `json:"id"`
	KDF  Argon2Params `json:"kdf"`
	AEAD AEADInfo     `json:"aead"`
	DEK  []byte       `json:"dek"`
}

// NewDEK returns a fresh random data-encryption key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// RandomHex returns n random bytes hex-encoded (2n characters).
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func deriveKEK(passphrase string, p Argon2Params) []byte {
	return argon2.IDKey([]byte(passphrase), p.Salt, p.T, p.M, uint8(p.P), DEKSize)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// AAD builds the additional authenticated data for a record: every
// ciphertext is bound to the format version, its role, and its position
// (docs/format-spec.md §2), so records cannot be replayed across vaults,
// roles, or positions.
func AAD(role, specific string) []byte {
	return []byte(fmt.Sprintf("coffer/%d/%s/%s", FormatVersion, role, specific))
}

// SealSlot creates a key slot sealing dek under passphrase.
func SealSlot(id int, passphrase string, dek []byte, vaultID string, params Argon2Params) (*Slot, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	if params.Salt == nil {
		params.Salt = make([]byte, SaltSize)
		if _, err := rand.Read(params.Salt); err != nil {
			return nil, err
		}
	}
	kek := deriveKEK(passphrase, params)
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, dek, AAD("meta-slot", slotSpecific(vaultID, id)))
	return &Slot{ID: id, KDF: params, AEAD: AEADInfo{Algo: AEADAlgo, Nonce: nonce}, DEK: sealed}, nil
}

// Open unseals the slot's DEK under passphrase. It returns ErrAuth when the
// passphrase is wrong or the slot was tampered with.
func (s *Slot) Open(passphrase, vaultID string) ([]byte, error) {
	if err := s.KDF.validate(); err != nil {
		return nil, err
	}
	if s.AEAD.Algo != AEADAlgo {
		return nil, fmt.Errorf("unsupported aead %q", s.AEAD.Algo)
	}
	// chacha20poly1305 panics on a wrong-length nonce; reject corrupted
	// slots with an error instead.
	if len(s.AEAD.Nonce) != NonceSize {
		return nil, fmt.Errorf("slot %d: malformed nonce length", s.ID)
	}
	kek := deriveKEK(passphrase, s.KDF)
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, s.AEAD.Nonce, s.DEK, AAD("meta-slot", slotSpecific(vaultID, s.ID)))
	if err != nil {
		return nil, ErrAuth
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("slot %d: unsealed DEK has wrong size", s.ID)
	}
	return dek, nil
}

func slotSpecific(vaultID string, id int) string {
	return vaultID + "/" + strconv.Itoa(id)
}

// SealManifest encrypts a manifest payload with the DEK under a fresh nonce.
// The result is nonce || ciphertext (nonce prepended, per spec §4).
func SealManifest(dek []byte, vaultID string, payload []byte) ([]byte, error) {
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, payload, AAD("manifest", vaultID))...), nil
}

// OpenManifest decrypts a nonce-prefixed manifest record.
func OpenManifest(dek []byte, vaultID string, record []byte) ([]byte, error) {
	if len(record) < NonceSize+TagSize {
		return nil, fmt.Errorf("manifest record too short")
	}
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, record[:NonceSize], record[NonceSize:], AAD("manifest", vaultID))
	if err != nil {
		return nil, ErrAuth
	}
	return payload, nil
}

// Hash returns the hex SHA-256 of data (used for the manifest chain).
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
