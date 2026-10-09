package vault

// Hardening tests: temp files inside the vault directory have predictable
// names; an attacker who briefly held the medium must not be able to plant
// a symlink that turns the next write into an arbitrary-file replacement.

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRejectsPlantedMetaTmpSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW is Unix-only; symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")

	target := filepath.Join(t.TempDir(), "precious.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, metaName+".tmp")); err != nil {
		t.Fatal(err)
	}

	if err := s.Rekey("new-pass"); err == nil {
		t.Fatal("rekey wrote through a planted vault.meta.tmp symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("symlink target was modified: %q (%v)", data, err)
	}
	// The vault itself is untouched and still opens with the old passphrase.
	if _, err := Open(dir, "pass"); err != nil {
		t.Fatalf("vault damaged by the refused write: %v", err)
	}
}

func TestRejectsPlantedManifestTmpSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW is Unix-only; symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")

	target := filepath.Join(t.TempDir(), "precious.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	next := s.manifestNum + 1
	if err := os.Symlink(target, filepath.Join(dir, manifestPrefix+strconv.Itoa(next)+".tmp")); err != nil {
		t.Fatal(err)
	}

	m := s.Manifest()
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("a", 40)}
	if err := s.Commit(m); err == nil {
		t.Fatal("commit wrote through a planted manifest.<n>.tmp symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("symlink target was modified: %q (%v)", data, err)
	}
}
