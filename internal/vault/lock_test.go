package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lockPath(dir string) string { return filepath.Join(dir, lockName) }

func TestLockFreshBlocksSecondWriter(t *testing.T) {
	dir := t.TempDir()
	release, _, err := acquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if _, err := os.Stat(lockPath(dir)); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
	_, _, err = acquireLock(dir)
	if err == nil || !strings.Contains(err.Error(), "another coffer operation") {
		t.Fatalf("second writer not blocked: %v", err)
	}
}

func TestLockStolenWhenOld(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().Add(-2 * lockStaleAfter)
	info := lockInfo{Host: "other-host", PID: 4242, Started: old}
	if err := writeLockFile(lockPath(dir), info); err != nil {
		t.Fatal(err)
	}
	// Normalize the mtime too: on FAT media the mtime is the fallback
	// staleness signal.
	os.Chtimes(lockPath(dir), old, old)

	release, guard, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("stale lock not stolen: %v", err)
	}
	defer release()
	if guard == info.String() {
		t.Fatal("stolen lock kept the old holder's identity")
	}
}

func TestLockStolenWhenHolderDeadOnSameHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("constructing a provably-dead pid is awkward on Windows; covered by TestPidAliveOnWindows")
	}
	dir := t.TempDir()
	cmd := exec.Command("sleep", "0")
	if err := cmd.Run(); err != nil {
		t.Fatalf("sacrificial holder: %v", err)
	}
	info := lockInfo{Host: hostname(), PID: cmd.Process.Pid, Started: time.Now().UTC()}
	if err := writeLockFile(lockPath(dir), info); err != nil {
		t.Fatal(err)
	}

	release, _, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("lock of dead holder not stolen: %v", err)
	}
	release()
}

func TestLockGarbageContentStolenWhenOld(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(lockPath(dir), []byte("\x00partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-2 * lockStaleAfter)
	if err := os.Chtimes(lockPath(dir), old, old); err != nil {
		t.Fatal(err)
	}

	release, _, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("unparseable stale lock not stolen: %v", err)
	}
	release()
}

func TestCommitAbortsWhenLockTakenOver(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "pass", weakParams())
	if err != nil {
		t.Fatal(err)
	}
	release, err := s.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a steal after lockStaleAfter: the lock now belongs to
	// someone else.
	os.WriteFile(lockPath(dir), []byte("host=thief\npid=1\nstarted=2026-01-01T00:00:00Z\n"), 0o600)

	m := s.Manifest()
	m.Refs["refs/heads/main"] = RefVal{OID: strings.Repeat("a", 40)}
	err = s.Commit(m)
	if err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("commit under a stolen lock succeeded: %v", err)
	}
	release()
}

// TestPidAliveOnWindows pins the Windows probe: the current process is
// alive; a pid from the reserved system range that cannot exist is not.
// Without the probe, a crashed Windows holder's lock blocked writes for
// the whole staleness window.
func TestPidAliveOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("exercises the Windows OpenProcess probe")
	}
	if !pidAlive(os.Getpid()) {
		t.Fatal("the running test process reports dead")
	}
	if pidAlive(0) || pidAlive(-1) {
		t.Fatal("invalid pids report alive")
	}
}
