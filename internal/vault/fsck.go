package vault

// fsck verifies every structure of a vault per spec §7: key-slot shapes,
// manifest authentication and the prev chain, the ref inventory, and full
// AEAD-plus-checksum validation of every object file. It reports the first
// divergence per structure and never attempts recovery.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Finding is one fsck observation. Err findings mean the vault is damaged
// (or inconsistent with its manifest); Info findings are hygiene items
// that coffer gc addresses.
type Finding struct {
	Structure string // "meta", "manifest", "chain", "refs", "obj", "hygiene"
	Detail    string
	Err       bool
}

func (f Finding) String() string {
	tag := "ok"
	if f.Err {
		tag = "error"
	} else if f.Detail != "" && f.Structure == "hygiene" {
		tag = "info"
	}
	return fmt.Sprintf("%-5s %-9s %s", tag, f.Structure, f.Detail)
}

// Fsck verifies the vault at dir. It returns findings — including Err
// ones — plus an error only when the vault cannot be opened at all (wrong
// passphrase, unreadable meta). A healthy vault yields no Err findings.
func Fsck(dir, passphrase string) ([]Finding, error) {
	var findings []Finding
	add := func(structure, detail string, isErr bool) {
		findings = append(findings, Finding{Structure: structure, Detail: detail, Err: isErr})
	}

	meta, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	s, err := Open(dir, passphrase)
	if err != nil {
		return nil, err
	}

	// meta: structural shape of every slot (per-slot authentication is
	// only provable for slots the passphrase opens).
	badSlots := 0
	for _, sl := range meta.Slots {
		if verr := sl.Validate(); verr != nil {
			add("meta", verr.Error(), true)
			badSlots++
		}
	}
	if badSlots == 0 {
		add("meta", fmt.Sprintf("format v%d, %d slot(s), all structurally valid", meta.FormatVersion, len(meta.Slots)), false)
	}

	// manifests: every generation on disk must authenticate and parse.
	gens := manifestGenerations(dir) // newest first
	if len(gens) == 0 {
		add("manifest", "no manifest generations found", true)
		return findings, nil
	}
	payloads := map[int]string{} // generation -> payload SHA-256
	manifestErrs := 0
	for _, n := range gens {
		_, hash, err := s.readManifestNum(n)
		if err != nil {
			add("manifest", fmt.Sprintf("generation %d: %v", n, err), true)
			manifestErrs++
			continue
		}
		payloads[n] = hash
	}
	if manifestErrs == 0 {
		add("manifest", fmt.Sprintf("%d generation(s) authenticate and parse", len(gens)), false)
	}

	// chain: each generation's prev must equal the payload hash of the
	// next-older generation present.
	chainErrs := 0
	for i, n := range gens {
		if i == len(gens)-1 {
			continue // oldest kept generation: prev points before the window
		}
		older := gens[i+1]
		m, _, err := s.readManifestNum(n)
		if err != nil {
			continue // already reported
		}
		if m.Prev == nil || *m.Prev != payloads[older] {
			got := "<null>"
			if m.Prev != nil {
				got = *m.Prev
			}
			chainErrs++
			if chainErrs == 1 { // first divergence per structure
				add("chain", fmt.Sprintf("generation %d: prev %s does not chain to generation %d (%s)", n, shortHash(got), older, shortHash(payloads[older])), true)
			}
		}
	}
	if chainErrs == 0 {
		add("chain", "prev chain intact across retained generations", false)
	}

	// refs: every ref's object must be in some pack's inventory.
	m := s.Manifest()
	inventory := map[string]bool{}
	for _, pack := range m.Packs {
		for _, oid := range pack.Objects {
			inventory[oid] = true
		}
	}
	refErrs := 0
	refNames := make([]string, 0, len(m.Refs))
	for name := range m.Refs {
		refNames = append(refNames, name)
	}
	sort.Strings(refNames)
	for _, name := range refNames {
		if !inventory[m.Refs[name].OID] {
			add("refs", fmt.Sprintf("%s points at %s, which no pack lists", name, shortHash(m.Refs[name].OID)), true)
			refErrs++
		}
	}
	if refErrs == 0 {
		add("refs", fmt.Sprintf("%d ref(s) covered by the pack inventory", len(refNames)), false)
	}

	// obj: every pack in the current manifest must exist and fully
	// authenticate, byte-for-byte, against its recorded checksum and size.
	packNames := make([]string, 0, len(m.Packs))
	for name := range m.Packs {
		packNames = append(packNames, name)
	}
	sort.Strings(packNames)
	referenced := map[string]bool{}
	for _, gen := range gens {
		gm, _, err := s.readManifestNum(gen)
		if err != nil {
			continue
		}
		for name := range gm.Packs {
			referenced[name] = true
		}
	}
	objErrs := 0
	for _, name := range packNames {
		sum, size, err := verifyObject(s, name)
		want := m.Packs[name]
		switch {
		case err != nil:
			add("obj", fmt.Sprintf("%s: %v", name, err), true)
			objErrs++
		case sum != want.SHA256:
			add("obj", fmt.Sprintf("%s: plaintext checksum %s, manifest records %s", name, shortHash(sum), shortHash(want.SHA256)), true)
			objErrs++
		case size != want.Size:
			add("obj", fmt.Sprintf("%s: plaintext size %d, manifest records %d", name, size, want.Size), true)
			objErrs++
		}
	}
	if objErrs == 0 {
		add("obj", fmt.Sprintf("%d object file(s) fully verified (AEAD, checksum, size)", len(packNames)), false)
	}

	// hygiene: orphans and leftovers — informational, gc removes them.
	entries, err := os.ReadDir(filepath.Join(dir, objDirName))
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !referenced[e.Name()] {
				add("hygiene", fmt.Sprintf("obj/%s is referenced by no generation (coffer gc removes it)", e.Name()), false)
			}
		}
	}
	rootEntries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range rootEntries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".tmp" {
				add("hygiene", fmt.Sprintf("%s is a leftover temp file (coffer gc removes it)", e.Name()), false)
			}
		}
	}
	return findings, nil
}

// verifyObject streams one object file through decryption, hashing the
// plaintext, and returns its hex SHA-256 and size.
func verifyObject(s *Store, name string) (string, int64, error) {
	rd, err := s.ReadObject(name)
	if err != nil {
		return "", 0, err
	}
	defer rd.Close()
	h := sha256.New()
	n, err := io.Copy(h, rd)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
