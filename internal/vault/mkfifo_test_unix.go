//go:build !windows

package vault

import "syscall"

func mkfifoForTest(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
