//go:build !windows

package vault

import (
	"os"
	"syscall"
)

// pidAlive reports whether pid names a live process (Unix signal 0
// probe).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
