// Package proto implements the git remote-helper conversation for
// coffer::<path> URLs (gitremote-helpers(7)) on top of the vault store.
// Object flow follows docs/architecture.md: push builds packs in the
// caller's repository, fetch imports objects into the caller's object
// database; no pack crosses the helper protocol in either direction.
package proto

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ziqing7226/Coffer/internal/packproc"
	"github.com/Ziqing7226/Coffer/internal/vault"
)

// Run executes the helper conversation for the vault at vaultDir. It returns
// when git closes the command stream, or with the error that should abort
// the git operation.
func Run(vaultDir string, in io.Reader, out io.Writer) error {
	s := &session{
		vaultDir: vaultDir,
		in:       bufio.NewReader(in),
		out:      bufio.NewWriter(out),
	}
	return s.loop()
}

type session struct {
	vaultDir string
	store    *vault.Store
	dryRun   bool
	in       *bufio.Reader
	out      *bufio.Writer
}

func (s *session) loop() error {
	var fetchBatch []string
	var pushBatch []string
	for {
		line, err := s.in.ReadString('\n')
		if line == "" && err != nil {
			return nil // git closed stdin: conversation over
		}
		cmd := strings.TrimRight(line, "\r\n")

		switch {
		case cmd == "capabilities":
			s.reply("option", "object-format", "list", "fetch", "push")

		case cmd == "list" || cmd == "list for-push":
			if err := s.listRefs(); err != nil {
				return err
			}

		case strings.HasPrefix(cmd, "option "):
			s.handleOption(strings.TrimPrefix(cmd, "option "))

		case strings.HasPrefix(cmd, "fetch "):
			if f := strings.Fields(cmd); len(f) >= 2 {
				fetchBatch = append(fetchBatch, f[1])
			}

		case strings.HasPrefix(cmd, "push "):
			pushBatch = append(pushBatch, strings.TrimPrefix(cmd, "push "))

		case cmd == "":
			if len(fetchBatch) > 0 {
				batch := fetchBatch
				fetchBatch = nil
				if err := s.serveFetch(batch); err != nil {
					return err
				}
			}
			if len(pushBatch) > 0 {
				batch := pushBatch
				pushBatch = nil
				if err := s.applyPush(batch); err != nil {
					return err
				}
			}

		default:
			// Unknown in-batch protocol lines are tolerated per
			// gitremote-helpers(7) (future push options and friends).
			fmt.Fprintf(os.Stderr, "git-remote-coffer: ignoring command %q\n", cmd)
		}
	}
}

// reply writes blank-line-terminated response lines and flushes.
func (s *session) reply(lines ...string) {
	for _, l := range lines {
		fmt.Fprintln(s.out, l)
	}
	fmt.Fprintln(s.out)
	s.out.Flush()
}

// replySingle writes a one-line response (option replies are single lines).
func (s *session) replySingle(line string) {
	fmt.Fprintln(s.out, line)
	s.out.Flush()
}

// openStore lazily opens the vault on first use, obtaining the passphrase
// through git's credential flow.
func (s *session) openStore() error {
	if s.store != nil {
		return nil
	}
	meta, err := vault.ReadMeta(s.vaultDir)
	if err != nil {
		return err
	}
	pass, err := GetPassphrase(meta.ID)
	if err != nil {
		return err
	}
	st, err := vault.Open(s.vaultDir, pass)
	if err != nil {
		return err
	}
	s.store = st
	return nil
}

func (s *session) handleOption(arg string) {
	f := strings.Fields(arg)
	if len(f) != 2 {
		s.replySingle("error malformed option")
		return
	}
	name, value := f[0], f[1]
	switch name {
	case "dry-run":
		switch value {
		case "true":
			s.dryRun = true
			s.replySingle("ok")
		case "false":
			s.dryRun = false
			s.replySingle("ok")
		default:
			s.replySingle("error dry-run expects true or false")
		}
	case "progress", "verbosity", "object-format":
		// Acknowledged; progress reporting and verbosity are cosmetic for
		// now, and the object-format keyword is always emitted in list.
		s.replySingle("ok")
	default:
		s.replySingle("unsupported")
	}
}

func (s *session) listRefs() error {
	if err := s.openStore(); err != nil {
		return err
	}
	m := s.store.Manifest()
	names := make([]string, 0, len(m.Refs))
	for name := range m.Refs {
		names = append(names, name)
	}
	sort.Strings(names)

	lines := []string{":object-format sha1"}
	for _, name := range names {
		lines = append(lines, m.Refs[name].OID+" "+name)
		if name == "refs/heads/main" || name == "refs/heads/master" {
			lines = append(lines, "@"+name+" HEAD")
		}
	}
	s.reply(lines...)
	return nil
}

// serveFetch answers a fetch batch: it decrypts the object files containing
// the requested objects into a scratch repository and imports the rebuilt
// pack into the caller's object database, then emits the batch-complete
// blank line.
func (s *session) serveFetch(oids []string) error {
	if err := s.openStore(); err != nil {
		return err
	}
	m := s.store.Manifest()

	// Every requested oid must be in the inventory; failing here beats a
	// confusing pack-objects error later.
	for _, oid := range oids {
		found := false
		for _, pack := range m.Packs {
			if oidInList(pack.Objects, oid) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("object %s is not in the vault inventory", oid)
		}
	}
	if len(m.Packs) == 0 {
		return fmt.Errorf("vault has no object files to serve")
	}

	// Decrypt ALL stored packs into the scratch repository: pack-objects
	// --revs walks the full history of the requested tips, and parents may
	// live in any pack. (Selective decryption needs reachability metadata
	// in the manifest; a later-phase optimization.)
	repo, cleanup, err := packproc.TempBareRepo()
	if err != nil {
		return err
	}
	defer cleanup()

	packDir := filepath.Join(repo, "objects", "pack")
	for name := range m.Packs {
		rd, err := s.store.ReadObject(name)
		if err != nil {
			return err
		}
		dst := filepath.Join(packDir, "pack-"+name+".pack")
		err = writeAllAndClose(rd, dst)
		if err != nil {
			return err
		}
		if err := packproc.IndexPackInDir(repo, dst); err != nil {
			return err
		}
	}

	if err := packproc.PipePackToCaller(repo, oids); err != nil {
		return err
	}
	fmt.Fprintln(s.out) // batch complete
	s.out.Flush()
	return nil
}

// applyPush applies a push batch: resolve ref updates, pull the missing
// objects from the caller's repository, store them as one encrypted object
// file, and commit the manifest (spec §6 ordering: objects, then manifest).
func (s *session) applyPush(specs []string) error {
	if err := s.openStore(); err != nil {
		return err
	}
	m := s.store.Manifest()
	byName := make(map[string]vault.RefVal, len(m.Refs))
	for name, rv := range m.Refs {
		byName[name] = rv
	}

	// Everything reachable from the vault's current tips is an exclusion,
	// so each push stores only missing objects (incremental pushes).
	var revs []string
	for _, rv := range m.Refs {
		if packproc.ExistsInCaller(rv.OID) {
			revs = append(revs, "^"+rv.OID)
		}
	}

	var report []string
	pushed := 0
	for _, spec := range specs {
		spec = strings.TrimPrefix(spec, "+")
		i := strings.Index(spec, ":")
		if i < 0 {
			report = append(report, fmt.Sprintf("error %s malformed push specification", spec))
			continue
		}
		src, dst := spec[:i], spec[i+1:]
		if src == "" { // ref deletion
			delete(byName, dst)
			report = append(report, "ok "+dst)
			continue
		}
		oid := src
		if !isHexOID(src) {
			resolved, err := packproc.ResolveInCaller(src)
			if err != nil {
				report = append(report, fmt.Sprintf("error %s %v", dst, err))
				continue
			}
			oid = resolved
		}
		byName[dst] = vault.RefVal{OID: oid}
		revs = append(revs, oid)
		pushed++
		report = append(report, "ok "+dst)
	}

	if pushed > 0 && !s.dryRun {
		if err := s.storeNewObjects(revs); err != nil {
			return err
		}
	}
	if !s.dryRun {
		m.Refs = byName
		if err := s.store.Commit(m); err != nil {
			return err
		}
	}
	s.reply(report...)
	return nil
}

// storeNewObjects builds one pack for revs in the caller's repository,
// verifies and inventories it, and stores it as a new encrypted object
// file. Packs with zero objects are not stored: pushing a ref that points
// at objects the vault already has yields an empty pack.
func (s *session) storeNewObjects(revs []string) error {
	packPath, cleanup, err := packproc.BuildPack(revs)
	if err != nil {
		return err
	}
	defer cleanup()

	count, err := packproc.ObjectCount(packPath)
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	oids, idxCleanup, err := packproc.IndexPack(packPath)
	if err != nil {
		return err
	}
	defer idxCleanup()

	f, err := os.Open(packPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	hasher := sha256.New()
	name, err := s.store.WriteObject(io.TeeReader(f, hasher))
	if err != nil {
		return err
	}
	s.store.Manifest().Packs[name] = vault.PackInfo{
		SHA256:  hex.EncodeToString(hasher.Sum(nil)),
		Size:    st.Size(),
		Objects: oids,
	}
	return nil
}

func writeAllAndClose(rd io.ReadCloser, dst string) error {
	defer rd.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, rd)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func oidInList(list []string, oid string) bool {
	for _, o := range list {
		if o == oid {
			return true
		}
	}
	return false
}

func isHexOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
