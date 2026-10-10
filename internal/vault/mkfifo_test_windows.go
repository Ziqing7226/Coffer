//go:build windows

package vault

import "errors"

func mkfifoForTest(path string) error {
	return errors.New("FIFOs are not created on Windows")
}
