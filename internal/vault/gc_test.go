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
