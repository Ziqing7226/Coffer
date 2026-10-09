package e2e

// The golden vault fixture pins cross-version readability: it was created
// by the v1.0.0-pre release binaries, and every future build must open,
// clone, and export it byte-identically. Frozen format plus this fixture
// means a vault written today stays readable forever — regressions fail
// here instead of in users' backups.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goldenPassphrase = "golden-pass"

func TestGoldenVaultFromV1_0_0Pre(t *testing.T) {
	base, err := filepath.Abs(filepath.Join("testdata", "golden-vault"))
	if err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(base, "vault.coffer")
	wantTipB, err := os.ReadFile(filepath.Join(base, "expected-tip.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantTip := strings.TrimSpace(string(wantTipB))

	// A fresh clone through the helper must reproduce the recorded tip
	// and content.
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), []string{"GIT_ASKPASS=" + writeAskpass(t.TempDir(), "askpass-golden", goldenPassphrase)},
		"clone", "-q", vaultURL(vaultDir), clone)
	if rev(t, clone, "main") != wantTip {
		t.Fatalf("golden vault tip = %s, want %s (recorded at fixture creation)", rev(t, clone, "main"), wantTip)
	}
	if got := git(t, clone, nil, "show", "main:golden.txt"); got != "golden fixture v1.0.0-pre\n" {
		t.Fatalf("golden fixture content drifted: %q", got)
	}

	// The exit path works on the fixture too: a bundle cloned by stock
	// git alone.
	bundleFile := filepath.Join(t.TempDir(), "golden.bundle")
	out, err := runGitcoffer(t, goldenPassphrase+"\n", "export-bundle", vaultDir, bundleFile)
	if err != nil {
		t.Fatalf("export-bundle on golden vault: %v\n%s", err, out)
	}
	fromBundle := filepath.Join(t.TempDir(), "from-bundle")
	git(t, t.TempDir(), nil, "clone", "-q", bundleFile, fromBundle)
	if rev(t, fromBundle, "main") != wantTip {
		t.Fatal("golden vault bundle tip mismatch")
	}
}
