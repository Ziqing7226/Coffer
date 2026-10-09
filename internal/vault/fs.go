package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// crashPoint is a fault-injection hook for tests (docs/development.md,
// fault injection): inert unless the COFFER_CRASH environment variable names
// this point, in which case the process exits immediately. The hook drops
// the writer lock before exiting: it simulates process death, and the
// stale-lock recovery that a real crash requires is exercised separately
// in the lock unit tests, so crash-recovery pushes stay immediate.
func (s *Store) crashPoint(name string) {
	if os.Getenv("COFFER_CRASH") == name {
		os.Remove(filepath.Join(s.dir, lockName))
		fmt.Fprintf(os.Stderr, "coffer: crash point %q hit\n", name)
		os.Exit(70)
	}
}

// syncDir flushes a directory entry so renames survive a crash. Directory
// fsync is not supported on Windows and is skipped there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeFileAtomic writes dir/name through a temp file, fsync, and rename
// (docs/format-spec.md §6), making the result all-or-nothing.
func writeFileAtomic(dir, name string, write func(*os.File) error) error {
	tmp := filepath.Join(dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
