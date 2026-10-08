package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ziqing7226/Coffer/internal/crypto"
)

const fakeOID = "0123456789012345678901234567890123456789"

func weakParams() crypto.Argon2Params {
	return crypto.Argon2Params{Algo: crypto.KDFAlgo, M: 16, T: 1, P: 1, Salt: bytes.Repeat([]byte{3}, 8)}
}

func TestCreateOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "pass-one", weakParams())
	if err != nil {
		t.Fatal(err)
	}
	if s.ManifestNum() != 1 {
		t.Fatalf("generation = %d, want 1", s.ManifestNum())
	}
	if len(s.Manifest().Refs) != 0 || len(s.Manifest().Packs) != 0 {
		t.Fatal("fresh vault is not empty")
	}
	if s.Meta().ID == "" || len(s.Meta().Slots) != 1 {
		t.Fatal("meta incomplete")
	}

	data := bytes.Repeat([]byte{0x5a}, 3_000_000)
	name, err := s.WriteObject(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifest()
	m.Packs[name] = PackInfo{SHA256: crypto.Hash(data), Size: int64(len(data)), Objects: []string{fakeOID}}
	m.Refs["refs/heads/main"] = RefVal{OID: fakeOID}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	if s.ManifestNum() != 2 {
		t.Fatalf("generation = %d, want 2", s.ManifestNum())
	}

	s2, err := Open(dir, "pass-one")
	if err != nil {
		t.Fatal(err)
	}
	if s2.ManifestNum() != 2 {
		t.Fatalf("reopened generation = %d, want 2", s2.ManifestNum())
	}
	if got := s2.Manifest().Refs["refs/heads/main"].OID; got != fakeOID {
		t.Fatalf("ref lost: %q", got)
	}
	if s2.Manifest().Prev == nil {
		t.Fatal("manifest chain (prev) missing")
	}
	rd, err := s2.ReadObject(name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	rd.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("object round trip mismatch")
	}
}

func TestMetaIsPlaintextAndSpecShaped(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "pw", weakParams()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vault.meta"))
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("vault.meta is not plaintext JSON: %v", err)
	}
	for _, key := range []string{"format_version", "id", "created", "slots"} {
		if _, ok := probe[key]; !ok {
			t.Fatalf("vault.meta missing key %q", key)
		}
	}
}

func TestOpenRejectsWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "right", weakParams()); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, "wrong")
	if !errors.Is(err, crypto.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestOpenNotVault(t *testing.T) {
	_, err := Open(t.TempDir(), "x")
	if !errors.Is(err, ErrNotVault) {
		t.Fatalf("want ErrNotVault, got %v", err)
	}
}

func TestUnsupportedFormatVersion(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "pw", weakParams()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "vault.meta"))
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["format_version"] = 99
	out, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, "vault.meta"), out, 0o600)
	if _, err := Open(dir, "pw"); err == nil {
		t.Fatal("future format version accepted")
	}
}

func TestGenerationPruneAndFallback(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "p", weakParams())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m := s.Manifest()
		m.Refs[fmt.Sprintf("refs/heads/b%d", i)] = RefVal{OID: fakeOID}
		if err := s.Commit(m); err != nil {
			t.Fatal(err)
		}
	}
	gens := GenerationNums(dir)
	if len(gens) != 2 || gens[0] != 4 || gens[1] != 3 {
		t.Fatalf("generations = %v, want [4 3]", gens)
	}

	// Corrupt the newest generation; Open must fall back to the previous
	// one (kept generations per spec §4).
	path := filepath.Join(dir, "manifest.4")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[10] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, "p")
	if err != nil {
		t.Fatalf("fallback open failed: %v", err)
	}
	if s2.ManifestNum() != 3 {
		t.Fatalf("fell back to generation %d, want 3", s2.ManifestNum())
	}
	if _, ok := s2.Manifest().Refs["refs/heads/b2"]; ok {
		t.Fatal("fell back to a generation that should be unreadable")
	}
}

func TestStrayFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "p", weakParams()); err != nil {
		t.Fatal(err)
	}
	// Simulate crash leftovers: an unreferenced object file and a stale
	// manifest temp file. Readers must ignore both.
	if err := os.WriteFile(filepath.Join(dir, objDirName, "ffff00112233445566778899aabbccddee"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.9.tmp"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, "p")
	if err != nil {
		t.Fatalf("open with stray files: %v", err)
	}
	if len(GenerationNums(dir)) != 1 || GenerationNums(dir)[0] != 1 {
		t.Fatalf("temp manifest counted as generation: %v", GenerationNums(dir))
	}
	if _, err := s.ReadObject("ffff00112233445566778899aabbccddee"); err == nil {
		t.Fatal("unreferenced object readable")
	}
}

func TestMissingObjectFileIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "p", weakParams())
	if err != nil {
		t.Fatal(err)
	}
	name, err := s.WriteObject(bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifest()
	m.Packs[name] = PackInfo{SHA256: crypto.Hash([]byte("payload")), Size: 7, Objects: []string{fakeOID}}
	m.Refs["refs/heads/main"] = RefVal{OID: fakeOID}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, objDirName, name)); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, "p")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.ReadObject(name); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
}
