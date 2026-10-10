package e2e

// Phase 3 end to end: key rotation and slots through the real CLI, the
// key-file second factor through real git pushes, gc after a crashed
// push, and fsck through the CLI on a healthy and a corrupted vault.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Ziqing7226/GitCoffer/internal/vault"
)

func exeExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// runGitcoffer runs the built CLI with stdin supplied (the non-terminal
// fallback reads each passphrase as one line).
func runGitcoffer(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "gitcoffer"+exeExt()), args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func openVaultPass(t *testing.T, dir, pass string) *vault.Store {
	t.Helper()
	s, err := vault.Open(dir, pass)
	if err != nil {
		t.Fatalf("opening vault: %v", err)
	}
	return s
}

func TestRekeyViaCLI(t *testing.T) {
	// Isolate from host credential helpers (Git Credential Manager on
	// Windows): a helper that remembered the pre-rekey passphrase would
	// answer git credential fill with the stale value and mask the test.
	emptyCfg := filepath.Join(t.TempDir(), "empty-gitconfig")
	if err := os.WriteFile(emptyCfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	isolated := []string{"GIT_CONFIG_GLOBAL=" + emptyCfg, "GIT_CONFIG_SYSTEM=" + emptyCfg}

	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, isolated, "push", "-q", "-u", "origin", "main")
	packsBefore := len(openVault(t, vaultDir).Manifest().Packs)

	out, err := runGitcoffer(t, passphrase+"\nrotated-pass\nrotated-pass\n", "rekey", vaultDir)
	if err != nil {
		t.Fatalf("gitcoffer rekey: %v\n%s", err, out)
	}
	if !strings.Contains(out, "slot 0") || !strings.Contains(out, "object data untouched") {
		t.Fatalf("rekey output lacks confirmation: %s", out)
	}
	// Direct, in-process check: the CLI sealed exactly this passphrase.
	if _, err := vault.Open(vaultDir, "rotated-pass"); err != nil {
		t.Fatalf("direct open with the rotated passphrase failed: %v", err)
	}

	// The old passphrase is dead everywhere, the new one works end to end.
	out = gitFail(t, src, append([]string{"GIT_ASKPASS=" + wrongPass}, isolated...), "push", "origin", "main")
	if !strings.Contains(out, "authentication failed") {
		t.Fatalf("old passphrase not rejected: %s", out)
	}
	rotated := writeAskpass(binDir, "askpass-rotated", "rotated-pass")
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	pushOut, pushErr := runGit(src, append([]string{"GIT_ASKPASS=" + rotated}, isolated...), "push", "-q", "origin", "main")
	if pushErr != nil {
		// Flatten: CI annotations are single-line.
		t.Fatalf("push after rekey failed: %v; output: %s",
			pushErr, strings.ReplaceAll(strings.TrimSpace(pushOut), "\n", " | "))
	}

	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), append([]string{"GIT_ASKPASS=" + rotated}, isolated...), "clone", "-q", vaultURL(vaultDir), clone)
	if rev(t, clone, "main") != rev(t, src, "main") {
		t.Fatal("clone after rekey has stale tip")
	}
	if got := len(openVaultPass(t, vaultDir, "rotated-pass").Manifest().Packs); got != packsBefore+1 {
		t.Fatalf("packs after rekey push = %d, want %d (rekey must not touch data)", got, packsBefore+1)
	}
}

func TestKeyFileThroughGit(t *testing.T) {
	vaultDir := newVault(t)
	keyfile := filepath.Join(t.TempDir(), "coffer.key")

	out, err := runGitcoffer(t, passphrase+"\nkeyfile-pass\nkeyfile-pass\n", "key", "add", "-keyfile", keyfile, vaultDir)
	if err != nil {
		t.Fatalf("gitcoffer key add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key file created") {
		t.Fatalf("key add output lacks the created-file notice: %s", out)
	}
	// Drop the passphrase-only slot: the vault now demands passphrase + key file.
	if out, err = runGitcoffer(t, "keyfile-pass\n", "key", "remove", vaultDir, "0"); err != nil {
		t.Fatalf("gitcoffer key remove: %v\n%s", err, out)
	}

	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	kfPass := writeAskpass(binDir, "askpass-keyfile", "keyfile-pass")
	git(t, src, []string{"GIT_ASKPASS=" + kfPass}, "push", "-q", "-u", "origin", "main")

	// Without the key file the push fails and names it.
	renamed := keyfile + ".away"
	os.Rename(keyfile, renamed)
	out = gitFail(t, src, []string{"GIT_ASKPASS=" + kfPass}, "push", "origin", "main")
	if !strings.Contains(out, "key file") {
		t.Fatalf("missing key file not named in the git-visible error: %s", out)
	}
	os.Rename(renamed, keyfile)
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	git(t, src, []string{"GIT_ASKPASS=" + kfPass}, "push", "-q", "origin", "main")
}

func TestGCAfterCrashedPush(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")

	// Crash after the object file is renamed into obj/ but before the
	// manifest commits: the object is an orphan no manifest references
	// (crashing any earlier leaves a .tmp file instead).
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	gitFail(t, src, []string{"COFFER_CRASH=after-object-rename"}, "push", "origin", "main")

	out, err := runGitcoffer(t, passphrase+"\n", "fsck", vaultDir)
	if err != nil {
		t.Fatalf("fsck after crash: %v\n%s", err, out)
	}
	if !strings.Contains(out, "gc removes it") {
		t.Fatalf("fsck did not flag the orphan: %s", out)
	}

	out, err = runGitcoffer(t, passphrase+"\n", "gc", "--prune", vaultDir)
	if err != nil {
		t.Fatalf("gitcoffer gc --prune: %v\n%s", err, out)
	}
	if !strings.Contains(out, "removed orphaned object") {
		t.Fatalf("gc --prune did not remove the orphan: %s", out)
	}

	// The vault is clean again and still accepts pushes.
	if out, err = runGitcoffer(t, passphrase+"\n", "fsck", vaultDir); err != nil {
		t.Fatalf("fsck after gc: %v\n%s", err, out)
	}
	git(t, src, nil, "push", "-q", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("recovery push after gc did not land")
	}
}

func TestFsckCLIDetectsCorruption(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")

	out, err := runGitcoffer(t, passphrase+"\n", "fsck", vaultDir)
	if err != nil {
		t.Fatalf("fsck on healthy vault: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no errors found") {
		t.Fatalf("healthy fsck output unexpected: %s", out)
	}

	// Flip one byte inside an object file's first chunk.
	s := openVault(t, vaultDir)
	var name string
	for n := range s.Manifest().Packs {
		name = n
		break
	}
	path := filepath.Join(vaultDir, "obj", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[2] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err = runGitcoffer(t, passphrase+"\n", "fsck", vaultDir)
	if err == nil {
		t.Fatalf("fsck on corrupted vault exited 0:\n%s", out)
	}
	if !strings.Contains(out, "error") || !strings.Contains(out, name) {
		t.Fatalf("fsck did not name the corrupted object:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("fsck found %d error", 1)) {
		t.Fatalf("fsck error summary missing:\n%s", out)
	}
}
