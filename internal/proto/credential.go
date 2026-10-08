package proto

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// GetPassphrase obtains the vault passphrase through `git credential fill`,
// which honors GIT_ASKPASS (set by VSCode), terminal prompts, and any
// configured credential helpers. The vault id participates in the request
// so stored credentials stay distinct per vault.
func GetPassphrase(vaultID string) (string, error) {
	cmd := exec.Command("git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=coffer\nhost=coffer\npath=" + vaultID + "\nusername=coffer\n\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("obtaining passphrase: %v: %s", err, stderr.String())
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "password="); ok && v != "" {
			return v, nil
		}
	}
	return "", errors.New("no passphrase supplied for the vault")
}
