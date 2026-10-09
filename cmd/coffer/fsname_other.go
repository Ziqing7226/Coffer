//go:build !darwin && !linux

package main

// filesystemName is a best-effort probe; other platforms report unknown.
func filesystemName(path string) (string, bool) {
	return "", false
}
