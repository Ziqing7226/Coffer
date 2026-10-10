//go:build windows

package vault

import (
	"golang.org/x/sys/windows"
)

// pidAlive reports whether pid names a live process on Windows:
// OpenProcess succeeds while the process exists (an access-denied result
// also means it exists — it is simply not ours to query), and a live
// process reports STILL_ACTIVE as its exit code.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const stillActive = 259 // WAIT_TIMEOUT
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Access denied means the process exists but is not queryable.
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true // cannot tell — assume alive (conservative)
	}
	return code == stillActive
}
