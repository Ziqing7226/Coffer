package e2e

// TestLargeRepositorySmoke is the 10k-commit timing-budget smoke test from
// docs/development.md (Phase 2). It is opt-in because it pushes real
// gigabytes-scale history around:
//
//	COFFER_E2E_LARGE=1 COFFER_E2E_LARGE_DIR=/run/media/... go test \
//	    ./internal/e2e -run TestLargeRepositorySmoke -v -timeout 40m
//
// COFFER_E2E_LARGE_DIR places the vault on real external media (e.g. a
// FAT32 USB drive) so the numbers reflect the deployment target; without
// it the vault lands in a TempDir on the test disk.

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ziqing7226/Coffer/internal/vault"
)

func TestLargeRepositorySmoke(t *testing.T) {
	if os.Getenv("COFFER_E2E_LARGE") != "1" {
		t.Skip("opt-in large smoke test; set COFFER_E2E_LARGE=1 and a generous -timeout")
	}

	const (
		commits       = 10000
		pushBudget    = 10 * time.Minute
		cloneBudget   = 10 * time.Minute
		updatesBudget = 2 * time.Minute
	)

	vaultDir := filepath.Join(t.TempDir(), "large-smoke.coffer")
	if dir := os.Getenv("COFFER_E2E_LARGE_DIR"); dir != "" {
		vaultDir = filepath.Join(dir, "large-smoke.coffer")
		os.RemoveAll(vaultDir)
	}
	if _, err := vault.Create(vaultDir, passphrase, weakParams); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, src, nil, "init", "-q", "-b", "main", ".")
	git(t, src, nil, "config", "user.name", testGitName)
	git(t, src, nil, "config", "user.email", testGitMail)
	buildLargeHistory(t, src, commits)
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	tip := rev(t, src, "main")

	started := time.Now()
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	pushDur := time.Since(started)
	t.Logf("push of %d commits took %s (budget %s)", commits, pushDur.Round(time.Millisecond), pushBudget)

	started = time.Now()
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	cloneDur := time.Since(started)
	if rev(t, clone, "origin/main") != tip {
		t.Fatal("clone tip mismatch after large push")
	}
	t.Logf("fresh clone took %s (budget %s)", cloneDur.Round(time.Millisecond), cloneBudget)

	started = time.Now()
	commit(t, src, "file.txt", "incremental\n", "smoke incremental")
	git(t, src, nil, "push", "-q", "origin", "main")
	incDur := time.Since(started)
	t.Logf("incremental push took %s (budget %s)", incDur.Round(time.Millisecond), updatesBudget)

	var stored int64
	filepath.WalkDir(vaultDir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, serr := d.Info(); serr == nil {
				stored += info.Size()
			}
		}
		return nil
	})
	packs := len(openVault(t, vaultDir).Manifest().Packs)
	t.Logf("vault on disk: %d bytes (%.1f MiB) across %d object files",
		stored, float64(stored)/(1<<20), packs)

	if pushDur > pushBudget {
		t.Errorf("full push exceeded budget: %s > %s", pushDur, pushBudget)
	}
	if cloneDur > cloneBudget {
		t.Errorf("fresh clone exceeded budget: %s > %s", cloneDur, cloneBudget)
	}
	if incDur > updatesBudget {
		t.Errorf("incremental push exceeded budget: %s > %s", incDur, updatesBudget)
	}
}

// buildLargeHistory creates n commits on refs/heads/main through
// git fast-import — the fastest way to materialize a many-commit history
// (seconds for 10k commits, versus minutes of process spawns with commit).
func buildLargeHistory(t *testing.T, dir string, n int) {
	t.Helper()
	var sb strings.Builder
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		content := fmt.Sprintf("content %d\n", i)
		msg := fmt.Sprintf("smoke commit %d\n", i)
		id := fmt.Sprintf("%s <%s> %d +0000", testGitName, testGitMail,
			base.Add(time.Duration(i)*time.Second).Unix())
		sb.WriteString(fmt.Sprintf("commit refs/heads/main\nmark :%d\nauthor %s\ncommitter %s\ndata %d\n%s",
			i, id, id, len(msg), msg))
		if i > 1 {
			sb.WriteString("from :" + strconv.Itoa(i-1) + "\n")
		}
		sb.WriteString(fmt.Sprintf("M 644 inline f%d\ndata %d\n%s\n",
			i%20, len(content), content))
	}
	cmd := exec.Command("git", "fast-import", "--quiet")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(sb.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v\n%s", err, out)
	}
}
