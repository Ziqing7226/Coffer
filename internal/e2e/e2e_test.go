// Package e2e drives real git against the built Coffer binaries: these are
// the golden protocol tests from docs/development.md. They build
// git-remote-coffer and coffer, put the helper on PATH, script the
// passphrase through GIT_ASKPASS (the same mechanism VSCode uses), and
// exercise clone/push/fetch against encrypted vaults.
package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Ziqing7226/Coffer/internal/crypto"
	"github.com/Ziqing7226/Coffer/internal/vault"
)

const (
	passphrase  = "e2e-passphrase"
	repoURLPfx  = "coffer::"
	testGitName = "E2E Tester"
	testGitMail = "e2e@example.invalid"
)

var (
	binDir     string
	askpass    string
	wrongPass  string
	emptyPass  string
	repoRoot   string
	weakParams = crypto.Argon2Params{Algo: crypto.KDFAlgo, M: 16, T: 1, P: 1}
)

func TestMain(m *testing.M) {
	var err error
	repoRoot, err = filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Binaries and askpass scripts must live on an executable filesystem:
	// TMPDIR may point at noexec media (FAT32 USB) for vault-data testing,
	// so the build directory goes under the repo's gitignored bin/ instead.
	binDir = filepath.Join(repoRoot, "bin", fmt.Sprintf("e2e-%d", os.Getpid()))
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	for _, target := range []struct{ out, pkg string }{
		{"git-remote-coffer" + exe, "./cmd/git-remote-coffer"},
		{"coffer" + exe, "./cmd/coffer"},
	} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(binDir, target.out), target.pkg)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "building %s: %v\n%s", target.pkg, err, out)
			os.Exit(1)
		}
	}

	askpass = writeAskpass(binDir, "askpass", passphrase)
	wrongPass = writeAskpass(binDir, "askpass-wrong", "not-the-passphrase")
	emptyPass = writeAskpass(binDir, "askpass-empty", "")

	os.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	os.Setenv("GIT_ASKPASS", askpass)

	code := m.Run()
	os.RemoveAll(binDir)
	os.Exit(code)
}

func writeAskpass(dir, name, answer string) string {
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		os.WriteFile(path+".bat", []byte("@echo "+answer+"\r\n"), 0o755)
		return path + ".bat"
	}
	os.WriteFile(path, []byte("#!/bin/sh\necho "+answer+"\n"), 0o755)
	return path
}

// git runs a git command expected to succeed and returns its output.
func git(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	out, err := runGit(dir, env, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

// gitFail runs a git command expected to fail and returns its output.
func gitFail(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	out, err := runGit(dir, env, args...)
	if err == nil {
		t.Fatalf("git %v unexpectedly succeeded:\n%s", args, out)
	}
	return out
}

func runGit(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// newVault creates an encrypted vault with test (weak) KDF parameters so
// the suite stays fast; the parameters are stored in and honored from the
// slot, so nothing about the format changes.
func newVault(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault.coffer")
	if _, err := vault.Create(dir, passphrase, weakParams); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newRepo creates a repository with one commit on main.
func newRepo(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, dir, nil, "init", "-q", "-b", "main", ".")
	git(t, dir, nil, "config", "user.name", testGitName)
	git(t, dir, nil, "config", "user.email", testGitMail)
	writeFile(t, dir, "file.txt", "one\n")
	git(t, dir, nil, "add", "file.txt")
	git(t, dir, nil, "commit", "-qm", "commit one")
	return dir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, path, content, msg string) {
	t.Helper()
	writeFile(t, dir, path, content)
	git(t, dir, nil, "add", path)
	git(t, dir, nil, "commit", "-qm", msg)
}

func rev(t *testing.T, dir, rev string) string {
	t.Helper()
	return strings.TrimSpace(git(t, dir, nil, "rev-parse", rev))
}

func vaultURL(dir string) string { return repoURLPfx + dir }

func openVault(t *testing.T, dir string) *vault.Store {
	t.Helper()
	s, err := vault.Open(dir, passphrase)
	if err != nil {
		t.Fatalf("opening vault: %v", err)
	}
	return s
}

func TestFullRoundTrip(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	// Initial push creates the refs and the first object file.
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	s := openVault(t, vaultDir)
	if got := s.Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatalf("vault ref = %s, want %s", got, rev(t, src, "main"))
	}
	if len(s.Manifest().Packs) != 1 {
		t.Fatalf("packs = %d, want 1", len(s.Manifest().Packs))
	}

	// Clone from the encrypted vault and verify content.
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	if rev(t, src, "main") != rev(t, clone, "origin/main") {
		t.Fatal("clone tip mismatch")
	}
	if got := git(t, clone, nil, "show", "main:file.txt"); got != "one\n" {
		t.Fatalf("clone content mismatch: %q", got)
	}

	// Incremental push stores a second object file; pull in the clone.
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	git(t, src, nil, "push", "-q", "origin", "main")
	s = openVault(t, vaultDir)
	if len(s.Manifest().Packs) != 2 {
		t.Fatalf("packs after incremental push = %d, want 2", len(s.Manifest().Packs))
	}
	git(t, clone, nil, "pull", "-q", "origin", "main")
	if rev(t, src, "main") != rev(t, clone, "main") {
		t.Fatal("pull tip mismatch")
	}

	// Branch and annotated tag round-trip through a fresh clone.
	git(t, src, nil, "branch", "feature")
	commit(t, src, "feature.txt", "feature\n", "commit feature")
	git(t, src, nil, "push", "-q", "origin", "feature")
	git(t, src, nil, "tag", "-a", "v1.0", "-m", "release")
	git(t, src, nil, "push", "-q", "origin", "v1.0")
	second := filepath.Join(t.TempDir(), "second")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), second)
	if rev(t, second, "refs/remotes/origin/feature") != rev(t, src, "feature") {
		t.Fatal("feature mismatch in fresh clone")
	}
	if rev(t, second, "refs/tags/v1.0") != rev(t, src, "v1.0") {
		t.Fatal("tag mismatch in fresh clone")
	}

	// Zero-object push (branch at an existing tip) stores nothing.
	packsBefore := len(openVault(t, vaultDir).Manifest().Packs)
	git(t, src, nil, "branch", "backup")
	git(t, src, nil, "push", "-q", "origin", "backup")
	if got := len(openVault(t, vaultDir).Manifest().Packs); got != packsBefore {
		t.Fatalf("zero-object push stored a pack (%d -> %d)", packsBefore, got)
	}

	// Force-push rewind propagates; deletion propagates with --prune.
	git(t, src, nil, "reset", "-q", "--hard", "HEAD~1")
	git(t, src, nil, "push", "-q", "-f", "origin", "main")
	git(t, second, nil, "fetch", "-q", "origin")
	if rev(t, second, "refs/remotes/origin/main") != rev(t, src, "main") {
		t.Fatal("forced rewind not propagated")
	}
	git(t, src, nil, "push", "-q", "origin", ":feature")
	git(t, second, nil, "fetch", "-q", "--prune", "origin")
	if out, err := runGit(second, nil, "rev-parse", "-q", "--verify", "refs/remotes/origin/feature"); err == nil {
		t.Fatalf("deleted ref still present after prune: %s", out)
	}

	// The final clone passes fsck.
	git(t, second, nil, "fsck", "--no-progress")

	// The vault directory contains no plaintext: object files and
	// manifests must not leak pack magic or ref names.
	entries, err := os.ReadDir(filepath.Join(vaultDir, "obj"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(vaultDir, "obj", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("PACK")) {
			t.Fatalf("object %s leaks plaintext pack magic", e.Name())
		}
		if bytes.Contains(data, []byte("refs/heads/")) {
			t.Fatalf("object %s leaks ref names", e.Name())
		}
	}
	mans, err := filepath.Glob(filepath.Join(vaultDir, "manifest.*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mans {
		data, _ := os.ReadFile(m)
		if bytes.Contains(data, []byte("refs/heads/")) {
			t.Fatalf("%s leaks ref names", filepath.Base(m))
		}
	}
}

func TestDryRunPushChangesNothing(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	out := git(t, src, nil, "push", "--dry-run", "origin", "main")
	if !strings.Contains(out, "main") {
		t.Fatalf("dry-run output lacks ref report: %q", out)
	}
	s := openVault(t, vaultDir)
	if len(s.Manifest().Refs) != 0 || len(s.Manifest().Packs) != 0 {
		t.Fatal("dry-run modified the vault")
	}
	// The real push still works afterwards.
	git(t, src, nil, "push", "-q", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("push after dry-run failed to store refs")
	}
}

// TestProgressReported verifies that push and fetch emit "coffer:" progress
// milestones on stderr when git requests progress (--progress), and stay
// quiet otherwise (git then sends "option progress false").
func TestProgressReported(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	out := git(t, src, nil, "push", "--progress", "-u", "origin", "main")
	if !strings.Contains(out, "coffer: ") {
		t.Fatalf("push --progress lacks coffer milestones: %s", out)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	out = git(t, t.TempDir(), nil, "clone", "--progress", "-q", vaultURL(vaultDir), clone)
	if !strings.Contains(out, "coffer: ") {
		t.Fatalf("clone --progress lacks coffer milestones: %s", out)
	}

	out = git(t, src, nil, "push", "-q", "origin", "main")
	if strings.Contains(out, "coffer: ") {
		t.Fatalf("quiet push unexpectedly reported progress: %s", out)
	}
}

// TestCredentialApprovedAfterSuccess verifies that a successful
// authentication is reported to git (git credential approve), so a
// configured credential helper remembers the passphrase — and that a wrong
// passphrase is never approved, so nothing stale gets cached.
func TestCredentialApprovedAfterSuccess(t *testing.T) {
	// Neutralize host-level credential helpers (e.g. Git Credential
	// Manager, configured system-wide on Windows runners) so the test sees
	// exactly the repository's store helper. Point at a real empty file:
	// "/dev/null" is not a valid path for the native Windows git.
	emptyCfg := filepath.Join(t.TempDir(), "empty-gitconfig")
	if err := os.WriteFile(emptyCfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	isolated := []string{"GIT_CONFIG_GLOBAL=" + emptyCfg, "GIT_CONFIG_SYSTEM=" + emptyCfg}

	credFile := filepath.Join(t.TempDir(), "creds")

	vaultDir := newVault(t)
	meta, err := vault.ReadMeta(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	// git runs a credential helper through a shell: backslashes in an
	// unquoted --file value would be eaten there, so use forward slashes
	// (valid on Windows too).
	git(t, src, nil, "config", "credential.helper", "store --file="+filepath.ToSlash(credFile))

	pushOut := git(t, src, isolated, "push", "-q", "-u", "origin", "main")
	data, err := os.ReadFile(credFile)
	if err != nil {
		// Flatten: CI annotations are single-line.
		t.Fatalf("credential helper wrote nothing after a successful push: %v; push output: %s",
			err, strings.ReplaceAll(strings.TrimSpace(pushOut), "\n", " | "))
	}
	// credential-store serializes as a URL (coffer://coffer:<pass>@coffer/<id>);
	// assert on content, not on the serialization format.
	for _, want := range []string{meta.ID, passphrase} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("stored credential lacks %q:\n%s", want, data)
		}
	}

	// A rejected passphrase must not be approved.
	credFile2 := filepath.Join(t.TempDir(), "creds")
	vaultDir2 := newVault(t)
	src2 := newRepo(t, "src2")
	git(t, src2, nil, "remote", "add", "origin", vaultURL(vaultDir2))
	git(t, src2, nil, "config", "credential.helper", "store --file="+filepath.ToSlash(credFile2))
	gitFail(t, src2, append([]string{"GIT_ASKPASS=" + wrongPass}, isolated...), "push", "origin", "main")
	if _, err := os.Stat(credFile2); err == nil {
		d, _ := os.ReadFile(credFile2)
		t.Fatalf("rejected passphrase was approved and cached:\n%s", d)
	}
}

// TestWriterLockBlocksAndRecovers verifies the vault writer lock end to
// end: a fresh foreign lock makes pushes fail with an actionable message
// and leaves the vault untouched; a stale lock is stolen so operation
// resumes without manual cleanup.
func TestWriterLockBlocksAndRecovers(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	tip := rev(t, src, "main")

	lock := filepath.Join(vaultDir, "vault.lock")
	fresh := []byte("host=someone-else\npid=999999\nstarted=" + time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(lock, fresh, 0o600); err != nil {
		t.Fatal(err)
	}

	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	out := gitFail(t, src, nil, "push", "--progress", "origin", "main")
	if !strings.Contains(out, "another coffer operation") {
		t.Fatalf("blocked push lacks lock diagnostic: %s", out)
	}
	// The aborted push must not end with a "done" milestone that reads
	// like success.
	if strings.Contains(out, "coffer: done in") {
		t.Fatalf("aborted push reported completion: %s", out)
	}
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != tip {
		t.Fatal("blocked push changed the vault")
	}

	// The lock outlived its staleness window (simulating a crashed holder:
	// started long ago): the next push steals it and succeeds.
	old := time.Now().UTC().Add(-20 * time.Minute)
	stale := []byte("host=someone-else\npid=999999\nstarted=" + old.Format(time.RFC3339) + "\n")
	if err := os.WriteFile(lock, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	git(t, src, nil, "push", "-q", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("push after stale-lock steal did not land")
	}
	if _, err := os.Stat(lock); err == nil {
		t.Fatal("lock file not removed after the push completed")
	}
}

// TestAtomicPushAndForceWithLease: --atomic pushes land every ref of the
// batch or none; --force-with-lease is a git-side check against the refs we
// advertise, so a stale lease is rejected before the vault is touched.
func TestAtomicPushAndForceWithLease(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	git(t, src, nil, "branch", "feature")
	commit(t, src, "feature.txt", "feature\n", "commit feature")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	git(t, src, nil, "push", "-q", "--atomic", "origin", "main", "feature")
	s := openVault(t, vaultDir)
	if got := s.Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("atomic push: main mismatch")
	}
	if got := s.Manifest().Refs["refs/heads/feature"].OID; got != rev(t, src, "feature") {
		t.Fatal("atomic push: feature mismatch")
	}

	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	// Committing inside the clone needs an identity: CI runner images ship
	// without a global git user.
	git(t, clone, nil, "config", "user.name", testGitName)
	git(t, clone, nil, "config", "user.email", testGitMail)
	commit(t, clone, "file.txt", "one\ntwo\nthree\n", "commit three")

	// Pretend the clone's view of origin/main is stale: force-with-lease
	// must reject the push and leave the vault untouched.
	git(t, clone, nil, "update-ref", "refs/remotes/origin/main", "refs/remotes/origin/main~1")
	out := gitFail(t, clone, nil, "push", "--force-with-lease", "origin", "main")
	if !strings.Contains(out, "rejected") && !strings.Contains(out, "stale") {
		t.Fatalf("stale lease not rejected: %s", out)
	}
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("stale-lease push changed the vault")
	}

	// With the lease refreshed, the same push succeeds.
	git(t, clone, nil, "fetch", "-q", "origin")
	git(t, clone, nil, "push", "-q", "--force-with-lease", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, clone, "main") {
		t.Fatal("force-with-lease push did not land")
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	out := gitFail(t, src, []string{"GIT_ASKPASS=" + wrongPass}, "push", "origin", "main")
	if !strings.Contains(out, "authentication failed") && !strings.Contains(out, "ErrAuth") {
		t.Fatalf("push with wrong passphrase lacks precise error: %s", out)
	}
	// The remedy must be a command that actually evicts the credential:
	// git credential reject reads attributes on stdin, not a URL argument.
	if !strings.Contains(out, "git credential reject") || !strings.Contains(out, "printf") {
		t.Fatalf("rejected passphrase lacks the eviction recipe: %s", out)
	}
	if _, err := vault.Open(vaultDir, passphrase); err != nil {
		t.Fatalf("vault damaged by rejected push: %v", err)
	}
}

func TestNoPassphraseRejected(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	gitFail(t, src, []string{"GIT_ASKPASS=" + emptyPass}, "push", "origin", "main")
	gitFail(t, src, []string{"GIT_ASKPASS=", "GIT_TERMINAL_PROMPT=0"}, "push", "origin", "main")
}

func TestMissingVaultFailsCleanly(t *testing.T) {
	src := newRepo(t, "src")
	missing := filepath.Join(t.TempDir(), "nope.coffer")
	git(t, src, nil, "remote", "add", "origin", vaultURL(missing))
	out := gitFail(t, src, nil, "push", "origin", "main")
	if !strings.Contains(out, "not a coffer vault") {
		t.Fatalf("missing vault error is not actionable: %s", out)
	}
}

// TestCrashPoints verifies crash safety (docs/development.md, fault
// injection): an abort at any write stage must leave a vault that opens and
// still accepts pushes.
func TestCrashPoints(t *testing.T) {
	for _, point := range []string{
		"after-object-write",
		"after-object-rename",
		"before-manifest-commit",
		"after-manifest-write",
		"after-manifest-commit",
	} {
		t.Run(point, func(t *testing.T) {
			vaultDir := newVault(t)
			src := newRepo(t, "src")
			git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

			// First push succeeds so the vault has a state to fall back to.
			git(t, src, nil, "push", "-q", "-u", "origin", "main")
			tip := rev(t, src, "main")

			// Second push crashes at the named point.
			commit(t, src, "file.txt", "one\ntwo\n", "commit two")
			newTip := rev(t, src, "main")
			gitFail(t, src, []string{"COFFER_CRASH=" + point}, "push", "origin", "main")

			// Crash safety invariant (spec §6): the vault must open and
			// hold exactly one of the two consistent states — the old tip
			// or the new one. Only after-manifest-commit can be the new
			// state; every earlier point must still hold the old tip.
			s := openVault(t, vaultDir)
			got := s.Manifest().Refs["refs/heads/main"].OID
			wantState := "old"
			if got == newTip {
				wantState = "new"
			}
			if got != tip && got != newTip {
				t.Fatalf("refs after crash at %s = %s: neither old (%s) nor new (%s) state", point, got, tip, newTip)
			}
			if point != "after-manifest-commit" && wantState != "old" {
				t.Fatalf("crash at %s left the new state committed before the manifest rename", point)
			}

			// A subsequent healthy push converges to the new tip either way.
			git(t, src, nil, "push", "-q", "origin", "main")
			s = openVault(t, vaultDir)
			if got := s.Manifest().Refs["refs/heads/main"].OID; got != newTip {
				t.Fatalf("recovery push after crash at %s did not land", point)
			}
		})
	}
}

func TestCorruptedObjectFailsPrecisely(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")

	// Flip one byte inside the first chunk of the stored object file.
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
	data[64] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	out := gitFail(t, t.TempDir(), nil, "clone", vaultURL(vaultDir), clone)
	if !strings.Contains(out, "chunk") {
		t.Fatalf("corrupted-object error lacks chunk context: %s", out)
	}
}

// TestMultiChunkObject exercises the 64 MiB chunk boundary with a large
// incompressible file.
func TestMultiChunkObject(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-chunk test needs a >64 MiB payload")
	}
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	big := filepath.Join(src, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(f, io.TeeReader(io.LimitReader(rand.Reader, 64<<20+1<<20), h)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	want := hex.EncodeToString(h.Sum(nil))

	git(t, src, nil, "add", "big.bin")
	git(t, src, nil, "commit", "-qm", "add big file")
	git(t, src, nil, "push", "-q", "origin", "main")

	// The stored object must span more than one chunk.
	s := openVault(t, vaultDir)
	var size int64
	for _, p := range s.Manifest().Packs {
		size += p.Size
	}
	if size <= 64<<20 {
		t.Fatalf("stored plaintext %d bytes: chunk boundary not exercised", size)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	gf, err := os.Open(filepath.Join(clone, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.New()
	if _, err := io.Copy(got, gf); err != nil {
		t.Fatal(err)
	}
	gf.Close()
	if hex.EncodeToString(got.Sum(nil)) != want {
		t.Fatal("multi-chunk object corrupted in transit")
	}
}
