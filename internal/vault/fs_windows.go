//go:build windows

package vault

import "os"

// createNoFollow opens (creating or truncating) a file. O_NOFOLLOW is
// Unix-only, and creating symlinks on Windows requires developer mode or
// elevated privileges, so the plain create is the baseline there; the
// Unix build additionally refuses to write through planted links.
func createNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}
