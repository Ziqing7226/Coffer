package vault

// fsck coverage: every structure, first divergence per structure.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFsckHealthyVault(t *testing.T) {
	dir := t.TempDir()
	storeWithObject(t, dir, "pass")
	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Err {
			t.Fatalf("healthy vault reported an error: %s", f)
		}
	}
	if len(findings) == 0 {
		t.Fatal("fsck reported nothing at all")
	}
}

func TestFsckCorruptChunk(t *testing.T) {
	dir := t.TempDir()
	_, name := storeWithObject(t, dir, "pass")
	data := objBytes(t, dir, name)
	data[2] ^= 0x80 // inside the first chunk
	os.WriteFile(filepath.Join(dir, objDirName, name), data, 0o600)

	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Err && f.Structure == "obj" && strings.Contains(f.Detail, name) {
			found = true
		}
	}
	if !found {
		t.Fatalf("corrupted chunk not reported: %v", findings)
	}
}

func TestFsckMissingObject(t *testing.T) {
	dir := t.TempDir()
	_, name := storeWithObject(t, dir, "pass")
	os.Remove(filepath.Join(dir, objDirName, name))

	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Err && f.Structure == "obj" && strings.Contains(f.Detail, "missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing object file not reported: %v", findings)
	}
}

func TestFsckChainBreak(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")

	// Keep three generations so the chain has interior links.
	m := s.Manifest()
	m.Generations.Kept = 3
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("a", 40)}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	m.Refs["refs/heads/topic"] = RefVal{OID: strings.Repeat("b", 40)}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	gens := manifestGenerations(dir) // newest first: [4, 3, 2]
	if len(gens) != 3 {
		t.Fatalf("generations = %v, want 3", gens)
	}
	// Delete the middle generation: the newest's prev then points past a
	// gap (deleting the oldest would just shrink the window — the oldest
	// generation's prev legitimately reaches before it).
	os.Remove(filepath.Join(dir, "manifest.3"))

	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Err && f.Structure == "chain" {
			found = true
		}
	}
	if !found {
		t.Fatalf("chain break not reported: %v", findings)
	}
}

func TestFsckOrphanIsInfo(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")
	if _, err := s.WriteObject(strings.NewReader("orphan")); err != nil {
		t.Fatal(err)
	}

	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Structure == "hygiene" && f.Err {
			t.Fatalf("orphan reported as an error, not hygiene: %s", f)
		}
	}
	sawInfo := false
	for _, f := range findings {
		if f.Structure == "hygiene" && strings.Contains(f.Detail, "gc") {
			sawInfo = true
		}
	}
	if !sawInfo {
		t.Fatalf("orphan not surfaced as hygiene info: %v", findings)
	}
}
