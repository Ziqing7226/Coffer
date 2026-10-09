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
	return parseCredential(stdout.String())
}

// parseCredential extracts the password attribute from `git credential`
// output. A trailing \r is trimmed defensively: Windows askpass scripts
// (.bat echo) end lines with CRLF, and any layer that passes it through
// verbatim would otherwise corrupt the passphrase.
func parseCredential(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "password="); ok {
			v = strings.TrimRight(v, "\r")
			if v != "" {
				return v, nil
			}
		}
	}
	return "", errors.New("no passphrase supplied for the vault: the terminal prompt, GIT_ASKPASS, or credential helper returned an empty value")
}

// ApprovePassphrase reports a successful authentication to git
// (`git credential approve`), so configured credential helpers may remember
// the passphrase. With no helper configured it is a no-op. It must only be
// called after the passphrase opened a key slot — never on failure, or a
// wrong passphrase would be cached.
func ApprovePassphrase(vaultID, pass string) error {
	cmd := exec.Command("git", "credential", "approve")
	cmd.Stdin = strings.NewReader("protocol=coffer\nhost=coffer\npath=" + vaultID + "\nusername=coffer\npassword=" + pass + "\n\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git credential approve: %v: %s", err, stderr.String())
	}
	return nil
}
