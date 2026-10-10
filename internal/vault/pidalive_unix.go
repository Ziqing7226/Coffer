//go:build !windows

package vault

import (
	"errors"
	"os"
	"syscall"
)

// pidAlive reports whether pid names a live process (Unix signal 0
// probe). Three outcomes: nil — alive; os.ErrProcessDone (a reaped
// child) or ESRCH — gone; anything else (e.g. EPERM for another user's
// live process) — assume alive, because stealing a running operation's
// lock would be worse than waiting out the staleness window.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	switch {
	case err == nil:
		return true
	case errors.Is(err, os.ErrProcessDone), errors.Is(err, syscall.ESRCH):
		return false
	default:
		return true
	}
}
