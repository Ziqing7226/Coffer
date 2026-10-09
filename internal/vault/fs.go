package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Ziqing7226/Coffer/internal/crypto"
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

// readLimited reads a whole file whose path or content may originate from
// untrusted on-media metadata (the key-file path from vault.meta, the
// writer lock, vault.meta itself). It refuses to follow a planted symlink
// (Unix), refuses non-regular files — a path like /dev/zero or a FIFO
// would otherwise read forever — and refuses files larger than max.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := openNoFollowReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, larger than the %d-byte limit", path, info.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, max)
	}
	return data, nil
}

// writeFileAtomic writes dir/name through a temp file, fsync, and rename
// (docs/format-spec.md §6), making the result all-or-nothing. The temp
// name carries a random suffix so concurrent writers never share one tmp
// file (an interleaved vault.meta would lock out the whole vault), and it
// is opened with O_NOFOLLOW on Unix: a planted symlink must fail the
// write, not redirect it.
func writeFileAtomic(dir, name string, write func(*os.File) error) error {
	suffix, err := crypto.RandomHex(6)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, name+"."+suffix+".tmp")
	f, err := createNoFollow(tmp)
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
