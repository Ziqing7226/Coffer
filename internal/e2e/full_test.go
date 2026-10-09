//go:build unix

package e2e

// TestDiskFullRobustness exercises every vault write path on a nearly full
// filesystem. It needs no root and no real disk: the test re-executes
// itself inside an unprivileged user namespace with a 1 MiB tmpfs mounted
// as the vault medium, then sweeps the free space from zero upward. After
// every push attempt — success or ENOSPC failure — the one-consistent-state
// invariant the crash tests enforce must hold: the vault opens, the ref is
// either the old tip or the new one, and fsck reports no errors.
//
// Run with:
//
//	COFFER_E2E_FULL=1 go test ./internal/e2e -run TestDiskFullRobustness -v -timeout 10m

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Ziqing7226/GitCoffer/internal/vault"
)

func TestDiskFullRobustness(t *testing.T) {
	if os.Getenv("COFFER_E2E_FULL") != "1" {
		t.Skip("opt-in; set COFFER_E2E_FULL=1 (requires unprivileged user namespaces)")
	}

	fullDir := os.Getenv("COFFER_FULL_DIR")
	if fullDir == "" {
		// Outer run: re-exec this test inside a user namespace with a tiny
		// tmpfs; the inner run sees COFFER_FULL_DIR and proceeds natively.
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skipf("unshare unavailable: %v", err)
		}
		if err := exec.Command("unshare", "--map-root-user", "--mount", "true").Run(); err != nil {
			t.Skipf("unprivileged user namespaces unavailable: %v", err)
		}
		base, err := os.MkdirTemp("", "coffer-full-ns-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(base)
		mnt := filepath.Join(base, "mnt")
		if err := os.Mkdir(mnt, 0o755); err != nil {
			t.Fatal(err)
		}
		script := fmt.Sprintf(
			`mount -t tmpfs -o size=1024k tmpfs %q && exec %q -test.run=^TestDiskFullRobustness$ -test.v`,
			mnt, os.Args[0])
		cmd := exec.Command("unshare", "--map-root-user", "--mount", "sh", "-c", script)
		cmd.Env = append(os.Environ(), "COFFER_E2E_FULL=1", "COFFER_FULL_DIR="+mnt)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("namespaced test run failed: %v", err)
		}
		return
	}

	// Inner run: fullDir is a 1 MiB tmpfs. The source repository lives on
	// the normal test filesystem; only the vault feels the pressure.
	free := func() int64 {
		var st syscall.Statfs_t
		if err := syscall.Statfs(fullDir, &st); err != nil {
			t.Fatal(err)
		}
		return int64(st.Bavail) * int64(st.Bsize)
	}
	filler := filepath.Join(fullDir, "filler")
	if err := os.WriteFile(filler, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// setFree adjusts the filler until the mount has roughly target bytes
	// free (tmpfs granularity is one page; a small residue is fine).
	setFree := func(target int64) {
		for i := 0; i < 12; i++ {
			f := free()
			delta := f - target
			if delta >= 0 && delta < 4096 {
				return
			}
			if delta > 0 {
				fh, err := os.OpenFile(filler, os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				chunk := delta
				if chunk > 1<<20 {
					chunk = 1 << 20
				}
				_, err = fh.Write(make([]byte, chunk))
				fh.Close()
				if err != nil && !isNoSpace(err) {
					t.Fatal(err)
				}
				continue
			}
			info, err := os.Stat(filler)
			if err != nil {
				t.Fatal(err)
			}
			shrink := int64(-delta)
			if shrink > info.Size() {
				shrink = info.Size()
			}
			if err := os.Truncate(filler, info.Size()-shrink); err != nil {
				t.Fatal(err)
			}
		}
	}

	vaultDir := filepath.Join(fullDir, "vault.coffer")
	if _, err := vault.Create(vaultDir, passphrase, weakParams); err != nil {
		t.Fatalf("init on the tiny mount: %v", err)
	}
	src := newRepo(t, "src")
	git(t, src, nil, "remote", "add", "origin", vaultURL(vaultDir))
	git(t, src, nil, "push", "-q", "-u", "origin", "main")
	landed := rev(t, src, "main")
	t.Logf("baseline push landed at %s with %d bytes free", short(landed), free())

	// Sweep free space upward: each attempt must either fully land or fully
	// fail, never half-apply, and never damage the vault.
	landedCount := 1
	for _, target := range []int64{0, 4096, 8192, 16384, 32768, 65536, 131072} {
		setFree(target)
		commit(t, src, "file.txt", fmt.Sprintf("v-%d\n", target), fmt.Sprintf("sweep at %d free", target))
		attempt := rev(t, src, "main")
		out, err := runGit(src, nil, "push", "origin", "main")

		s := openVault(t, vaultDir)
		got := s.Manifest().Refs["refs/heads/main"].OID
		switch {
		case err == nil && got != attempt:
			t.Fatalf("push reported success at %d free but vault tip is %s, not %s", target, short(got), short(attempt))
		case err != nil && got == attempt:
			t.Fatalf("push failed at %d free but the vault advanced anyway", target)
		case err != nil && got != landed:
			t.Fatalf("push failed at %d free but vault tip %s is neither the landed %s nor the attempted %s",
				target, short(got), short(landed), short(attempt))
		}
		if err == nil {
			landed, landedCount = attempt, landedCount+1
		} else {
			t.Logf("free=%-6d push refused: %s", target, strings.ReplaceAll(strings.TrimSpace(out), "\n", " | "))
		}

		findings, ferr := vault.Fsck(vaultDir, passphrase)
		if ferr != nil {
			t.Fatalf("fsck could not run at %d free: %v", target, ferr)
		}
		for _, f := range findings {
			if f.Err {
				t.Fatalf("fsck error after push attempt at %d free: %s", target, f)
			}
		}
	}
	t.Logf("sweep done: %d of 8 pushes landed, vault consistent throughout", landedCount)

	// Rekey at zero free space must fail cleanly and leave the old
	// passphrase working.
	setFree(0)
	out, err := runGitcoffer(t, passphrase+"\nspun-pass\nspun-pass\n", "rekey", vaultDir)
	if err == nil {
		t.Logf("rekey at ~0 free unexpectedly succeeded (small enough meta?): %s", out)
		if _, oerr := vault.Open(vaultDir, "spun-pass"); oerr != nil {
			t.Fatal("rekey claimed success but the new passphrase does not open the vault")
		}
	} else {
		t.Logf("rekey at ~0 free refused: %s", strings.ReplaceAll(strings.TrimSpace(out), "\n", " | "))
		if _, oerr := vault.Open(vaultDir, passphrase); oerr != nil {
			t.Fatalf("failed rekey damaged the vault: %v", oerr)
		}
	}

	// Recovery: free everything, the next push must succeed; gc must run;
	// a fresh clone must match the source exactly.
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	commit(t, src, "file.txt", "recovered\n", "recovery commit")
	git(t, src, nil, "push", "-q", "origin", "main")
	if got := openVault(t, vaultDir).Manifest().Refs["refs/heads/main"].OID; got != rev(t, src, "main") {
		t.Fatal("recovery push did not land")
	}
	if out, err := runGitcoffer(t, passphrase+"\n", "gc", vaultDir); err != nil {
		t.Fatalf("gc after recovery: %v\n%s", err, out)
	}
	findings, err := vault.Fsck(vaultDir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Err {
			t.Fatalf("fsck error after recovery: %s", f)
		}
	}
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, t.TempDir(), nil, "clone", "-q", vaultURL(vaultDir), clone)
	if rev(t, clone, "main") != rev(t, src, "main") {
		t.Fatal("post-recovery clone tip mismatch")
	}
	t.Logf("recovery verified: %d commits in clone, fsck clean, %d bytes free", countCommits(t, clone), free())
}

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) ||
		(err != nil && strings.Contains(err.Error(), "no space"))
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func countCommits(t *testing.T, dir string) int {
	t.Helper()
	out := git(t, dir, nil, "rev-list", "--count", "HEAD")
	n := 0
	fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
	return n
}
