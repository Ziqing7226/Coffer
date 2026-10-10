//go:build !windows

package vault

import (
	"os"
	"syscall"
)

// createNoFollow opens (creating or truncating) a file that must not be a
// symlink: O_NOFOLLOW fails the open with ELOOP instead of writing through
// a planted link. Every temp file written into the vault directory goes
// through here — their names are predictable, and the directory may sit on
// media an attacker briefly held.
func createNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openNoFollowReadOnly opens a file for reading without following a final
// symlink component, and without blocking on FIFOs or devices.
func openNoFollowReadOnly(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
