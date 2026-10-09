package vault

// Corruption-matrix expansion: truncation of every structure and
// generation rollback via re-filing — each must produce a precise
// error, never a panic or a silent wrong answer. (Chunk transposition
// lives in the crypto package tests.)

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Ziqing7226/GitCoffer/internal/crypto"
)

func truncateFile(t *testing.T, path string, keep int64) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) <= keep {
		t.Fatalf("%s is already shorter than %d bytes", path, keep)
	}
	if err := os.WriteFile(path, data[:keep], 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedStructuresFailPrecisely(t *testing.T) {
	t.Run("meta", func(t *testing.T) {
		dir := t.TempDir()
		storeWithObject(t, dir, "pass")
		path := filepath.Join(dir, metaName)
		truncateFile(t, path, fileSize(path)/2)
		_, err := Open(dir, "pass")
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("truncated meta: %v", err)
		}
	})

	t.Run("manifest", func(t *testing.T) {
		dir := t.TempDir()
		storeWithObject(t, dir, "pass")
		gens := manifestGenerations(dir)
		path := filepath.Join(dir, manifestPrefix+strconv.Itoa(gens[0]))
		truncateFile(t, path, 40) // nonce prefix, no full ciphertext
		findings, err := Fsck(dir, "pass")
		if err != nil {
			t.Fatal(err)
		}
		saw := false
		for _, f := range findings {
			if f.Err && (f.Structure == "manifest" || f.Structure == "chain") {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("truncated manifest not reported: %v", findings)
		}
	})

	t.Run("object", func(t *testing.T) {
		dir := t.TempDir()
		_, name := storeWithObject(t, dir, "pass")
		path := filepath.Join(dir, objDirName, name)
		truncateFile(t, path, int64(crypto.NonceSize)+10) // nonce + partial ciphertext
		findings, err := Fsck(dir, "pass")
		if err != nil {
			t.Fatal(err)
		}
		saw := false
		for _, f := range findings {
			if f.Err && f.Structure == "obj" {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("truncated object not reported: %v", findings)
		}
	})
}

func TestGenerationRollbackIsDetected(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass")

	// Commit twice so several generations exist, then re-file the OLDEST
	// generation under the highest number: the rollback an attacker with
	// an earlier medium image can perform.
	m := s.Manifest()
	m.Generations.Kept = 4 // keep enough generations to re-file the oldest
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("a", 40)}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("b", 40)}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	gens := manifestGenerations(dir) // newest first
	if len(gens) < 3 {
		t.Fatalf("generations = %v, want at least 3", gens)
	}
	oldest := filepath.Join(dir, manifestPrefix+strconv.Itoa(gens[len(gens)-1]))
	data, err := os.ReadFile(oldest)
	if err != nil {
		t.Fatal(err)
	}
	highest := gens[0]
	if err := os.WriteFile(filepath.Join(dir, manifestPrefix+strconv.Itoa(highest+1)), data, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Fsck(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	saw := false
	for _, f := range findings {
		if f.Err && f.Structure == "chain" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("rolled-back generation not flagged by the chain check: %v", findings)
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
