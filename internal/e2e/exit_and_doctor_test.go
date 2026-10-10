package e2e

// End-to-end coverage for the 1.0.0 exit-and-trust features:
// export-bundle (the plain-git exit path), doctor, gc --dry-run, and
// the Git LFS pointer warning.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportBundleRoundTrip(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	git(t, src, nil, "checkout", "-q", "-b", "feature")
	commit(t, src, "feature.txt", "feature\n", "commit feature")
	git(t, src, nil, "checkout", "-q", "main")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "--atomic", "origin", "main", "feature")
	git(t, src, nil, "tag", "-a", "v1.0", "-m", "release")
	git(t, src, nil, "push", "-q", "origin", "v1.0")

	bundleFile := filepath.Join(t.TempDir(), "exported.bundle")
	out, err := runGitcoffer(t, passphrase+"\n", "export-bundle", vaultDir, bundleFile)
	if err != nil {
		t.Fatalf("gitcoffer export-bundle: %v\n%s", err, out)
	}
	if !strings.Contains(out, "3 ref(s)") {
		t.Fatalf("unexpected export summary: %s", out)
	}

	// Stock git alone can verify and clone the bundle — no Coffer involved.
	verify := git(t, src, nil, "bundle", "verify", bundleFile)
	// Locale-independent: verify lists the bundled ref names.
	if !strings.Contains(verify, "refs/heads/main") && !strings.Contains(verify, "main") {
		t.Fatalf("git bundle verify output unexpected: %s", verify)
	}
	fromBundle := filepath.Join(t.TempDir(), "from-bundle")
	git(t, t.TempDir(), nil, "clone", "-q", bundleFile, fromBundle)
	if rev(t, fromBundle, "main") != rev(t, src, "main") {
		t.Fatal("bundle clone main tip mismatch")
	}
	if rev(t, fromBundle, "refs/tags/v1.0") != rev(t, src, "refs/tags/v1.0") {
		t.Fatal("bundle clone tag mismatch")
	}
	if got := git(t, fromBundle, nil, "show", "origin/feature:feature.txt"); got != "feature\n" {
		t.Fatalf("bundle clone feature content mismatch: %q", got)
	}
	if _, err := os.Stat(filepath.Join(fromBundle, "file.txt")); err != nil {
		t.Fatal("bundle clone checked out no working tree")
	}
}

func TestExportBundleRefusesOverwrite(t *testing.T) {
	vaultDir := newVault(t)
	existing := filepath.Join(t.TempDir(), "out.bundle")
	os.WriteFile(existing, []byte("precious"), 0o644)
	out, err := runGitcoffer(t, "", "export-bundle", vaultDir, existing)
	if err == nil || !strings.Contains(out, "refusing to overwrite") {
		t.Fatalf("overwrite not refused: %v\n%s", err, out)
	}
}

func TestDoctor(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")

	out, err := runGitcoffer(t, "", "doctor", vaultDir)
	if err != nil {
		t.Fatalf("doctor on a healthy vault failed: %v\n%s", err, out)
	}
	for _, want := range []string{"[ok]   git", "[ok]   git-remote-coffer", "[ok]   vault.meta valid", "[ok]   manifest generations", "[ok]   object files"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output lacks %q:\n%s", want, out)
		}
	}

	// A missing key file is a warning, not a failure — but it must appear.
	keyfile := filepath.Join(t.TempDir(), "coffer.key")
	if _, err2 := runGitcoffer(t, passphrase+"\nkp-pass\nkp-pass\n", "key", "add", "-keyfile", keyfile, vaultDir); err2 != nil {
		t.Fatalf("key add: %v", err2)
	}
	os.Remove(keyfile)
	out, err = runGitcoffer(t, "", "doctor", vaultDir)
	if err != nil {
		t.Fatalf("doctor failed on a warnable vault: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[warn] slot 1 key file missing") {
		t.Fatalf("doctor missed the absent key file:\n%s", out)
	}

	// A corrupt vault.meta is a failure.
	os.Remove(filepath.Join(vaultDir, "vault.meta"))
	os.WriteFile(filepath.Join(vaultDir, "vault.meta"), []byte("not json"), 0o600)
	out, err = runGitcoffer(t, "", "doctor", vaultDir)
	if err == nil || !strings.Contains(out, "[fail]") {
		t.Fatalf("doctor did not fail on a corrupt vault.meta: %v\n%s", err, out)
	}
}

func TestGCDryRunDeletesNothing(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	commit(t, src, "file.txt", "one\ntwo\n", "commit two")
	gitFail(t, src, []string{"COFFER_CRASH=after-object-rename"}, "push", "origin", "main") // leaves an orphan

	out, err := runGitcoffer(t, passphrase+"\n", "gc", "--dry-run", vaultDir)
	if err != nil {
		t.Fatalf("gc --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would remove orphaned object") {
		t.Fatalf("dry-run report missing the orphan: %s", out)
	}
	if got := len(openVault(t, vaultDir).Manifest().Packs); got != 1 {
		t.Fatalf("dry-run changed the vault: %d packs", got)
	}

	out, err = runGitcoffer(t, passphrase+"\n", "gc", vaultDir)
	if err != nil {
		t.Fatalf("gc: %v\n%s", err, out)
	}
	if !strings.Contains(out, "removed orphaned object") {
		t.Fatalf("gc did not remove the orphan: %s", out)
	}
}

func TestLFSPushWarns(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	os.WriteFile(filepath.Join(src, ".gitattributes"), []byte("*.bin filter=lfs diff=lfs merge=lfs -text\n"), 0o644)
	git(t, src, nil, "add", ".gitattributes")
	git(t, src, nil, "commit", "-qm", "enable lfs")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))

	out, err := runGit(src, nil, "push", "-u", "origin", "main")
	if err != nil {
		t.Fatalf("push with LFS attributes failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Git LFS") || !strings.Contains(out, "NOT stored in the vault") {
		t.Fatalf("LFS warning missing from push output:\n%s", out)
	}
}

// TestNonFastForwardProtection pins the server-side ancestry contract:
// pushing unrelated or rewritten history over an existing vault branch
// is rejected (the caller cannot be trusted to have checked), while a
// genuine fast-forward and an explicit --force pass. Without this, an
// unrelated push silently overwrites the branch and the overwritten
// commits are unrecoverable after gc.
func TestNonFastForwardProtection(t *testing.T) {
	vaultDir := newVault(t)
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	landed := rev(t, src, "main")

	// An unrelated repository with no common history.
	other := filepath.Join(t.TempDir(), "other")
	os.MkdirAll(other, 0o755)
	git(t, other, nil, "init", "-q", "-b", "main", ".")
	git(t, other, nil, "config", "user.name", "O")
	git(t, other, nil, "config", "user.email", "o@inv.alid")
	writeFile(t, other, "unrelated.txt", "different universe\n")
	git(t, other, nil, "add", ".")
	git(t, other, nil, "commit", "-qm", "unrelated history")
	git(t, other, nil, "remote", "add", "origin", vaultURL(vaultDir))

	out := gitFail(t, other, nil, "push", "origin", "main")
	if !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("unrelated push not rejected as non-fast-forward: %s", out)
	}
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != landed {
		t.Fatal("rejected non-fast-forward push changed the vault")
	}

	// The same history with an explicit force lands.
	git(t, other, nil, "push", "-q", "--force", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, other, "main") {
		t.Fatal("forced overwrite did not land")
	}

	// And the legitimate relay: a clone of the vault pushes a descendant.
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	commit(t, clone, "f", "relay\n", "relay commit")
	git(t, clone, nil, "push", "-q", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, clone, "main") {
		t.Fatal("legitimate fast-forward relay did not land")
	}
}
