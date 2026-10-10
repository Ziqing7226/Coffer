package vault

// gc coverage: orphaned objects, temp files, generation pruning.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGCSweepsOrphansAndTmp(t *testing.T) {
	dir := t.TempDir()
	s, referenced := storeWithObject(t, dir, "pass")

	// An orphan: written but never committed to any manifest.
	orphan, err := s.WriteObject(strings.NewReader("orphan-pack"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, objDirName, referenced+".tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.99.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := GC(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.RemovedObjects) != 1 || rep.RemovedObjects[0] != orphan {
		t.Fatalf("gc removed %v, want the orphan %s", rep.RemovedObjects, orphan)
	}
	if len(rep.RemovedTmp) != 2 {
		t.Fatalf("gc removed %v temp files, want 2", rep.RemovedTmp)
	}
	if _, err := os.Stat(filepath.Join(dir, objDirName, referenced)); err != nil {
		t.Fatal("gc removed a referenced object file")
	}
	if rep.BytesFreed == 0 {
		t.Fatal("gc reported nothing freed")
	}

	// The vault still opens and serves after gc.
	if _, err := Open(dir, "pass"); err != nil {
		t.Fatal(err)
	}
}

func TestGCRequiresTheWriterLock(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")

	// A concurrent writer holds the lock: gc must refuse rather than
	// sweep against a frozen reference set (it could otherwise delete an
	// object the writer is about to commit).
	release, err := s.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	_, err = GC(dir, "pass")
	if err == nil || !strings.Contains(err.Error(), "another coffer operation") {
		t.Fatalf("gc ran while the writer lock was held: %v", err)
	}
	release()

	if _, err := GC(dir, "pass"); err != nil {
		t.Fatalf("gc after lock release failed: %v", err)
	}
}

func TestGCRefusesBrokenGeneration(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")
	gens := manifestGenerations(dir)
	if len(gens) == 0 {
		t.Fatal("no generations")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "manifest.1"))
	data[len(data)-3] ^= 0x80
	os.WriteFile(filepath.Join(dir, "manifest.1"), data, 0o600)
	_ = s

	if _, err := GC(dir, "pass"); err == nil || !strings.Contains(err.Error(), "fsck") {
		t.Fatalf("gc did not refuse a broken vault: %v", err)
	}
}

func TestGCDryRunReportsPrunableGenerations(t *testing.T) {
	dir := t.TempDir()
	storeWithObject(t, dir, "pass")
	s := openStore(t, dir, "pass")
	m := s.Manifest()
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("a", 40)}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}

	// Simulate drift: a generation beyond the kept bound left on disk
	// (e.g. assembled from copies). Dry-run must report it without
	// deleting; a real pass must delete it.
	pristine := filepath.Join(dir, "manifest.2")
	drifted := filepath.Join(dir, "manifest.1")
	data, err := os.ReadFile(pristine)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drifted, data, 0o600); err != nil {
		t.Fatal(err)
	}

	dry, err := GCDryRun(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.PrunedGenerations) != 1 || dry.PrunedGenerations[0] != 1 {
		t.Fatalf("dry-run prunable report = %v, want [1]", dry.PrunedGenerations)
	}
	if _, err := os.Stat(drifted); err != nil {
		t.Fatal("dry-run deleted the drifted generation")
	}

	rep, err := GC(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PrunedGenerations) != 1 || rep.PrunedGenerations[0] != 1 {
		t.Fatalf("real pass prunable report = %v, want [1]", rep.PrunedGenerations)
	}
}

func openStore(t *testing.T, dir, pass string) *Store {
	t.Helper()
	s, err := Open(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenWarnsViaFallbackField(t *testing.T) {
	dir := t.TempDir()
	storeWithObject(t, dir, "pass")
	// gen 2 is now newest; corrupt it so Open must fall back to gen 1.
	path := filepath.Join(dir, "manifest.2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, data[:len(data)-3], 0o600)

	s2, err := Open(dir, "pass")
	if err != nil {
		t.Fatalf("fallback open failed: %v", err)
	}
	if s2.FallbackFromGeneration() != 2 {
		t.Fatalf("fallback = %d, want 2", s2.FallbackFromGeneration())
	}
	if s2.ManifestNum() != 1 {
		t.Fatalf("effective generation = %d, want 1", s2.ManifestNum())
	}
}
