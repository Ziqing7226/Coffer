package proto

// Session-level protocol tests: the helper conversation driven directly,
// without git — these pin behaviors that real git rarely triggers, like a
// failed ref inside an --atomic batch.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ziqing7226/GitCoffer/internal/crypto"
	"github.com/Ziqing7226/GitCoffer/internal/vault"
)

// driveSession runs a scripted conversation against Run and returns the
// helper's raw stdout. The caller repo at repoDir supplies object
// resolution; askpass echoes the passphrase.
func driveSession(t *testing.T, repoDir, vaultDir string, lines ...string) string {
	t.Helper()
	askpass := filepath.Join(t.TempDir(), "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho test-pass\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdir, _ := os.Getwd()
	os.Chdir(repoDir)
	defer os.Chdir(wdir)

	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out strings.Builder
	oldAskpass := os.Getenv("GIT_ASKPASS")
	os.Setenv("GIT_ASKPASS", askpass)
	defer os.Setenv("GIT_ASKPASS", oldAskpass)
	if err := Run(vaultDir, in, &out); err != nil {
		t.Fatalf("session aborted: %v", err)
	}
	return out.String()
}

func TestAtomicBatchReportsAllOrNothing(t *testing.T) {
	vaultDir := t.TempDir()
	if _, err := vault.Create(vaultDir, "test-pass", crypto.Argon2Params{Algo: crypto.KDFAlgo, M: 16, T: 1, P: 1}); err != nil {
		t.Fatal(err)
	}

	// A caller repository with one commit so HEAD resolves.
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main", "."},
		{"config", "user.name", "T"},
		{"config", "user.email", "t@inv.alid"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.WriteFile(filepath.Join(repo, "f"), []byte("x\n"), 0o644)
	for _, args := range [][]string{{"add", "."}, {"commit", "-qm", "c"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	out := driveSession(t, repo, vaultDir,
		"option atomic true",
		"list for-push",
		"push HEAD:refs/heads/alpha",
		"push no-such-ref-zzz:refs/heads/beta",
		"",
	)

	if !strings.Contains(out, "error refs/heads/beta") {
		t.Fatalf("failed ref not reported as error:\n%s", out)
	}
	if !strings.Contains(out, "error refs/heads/alpha atomic batch aborted") {
		t.Fatalf("atomic batch reported a ref as ok without committing it:\n%s", out)
	}
	if strings.Contains(out, "ok refs/heads/alpha") {
		t.Fatalf("atomic batch leaked an ok line:\n%s", out)
	}
	// Nothing was stored: the vault has no refs.
	s, err := vault.Open(vaultDir, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Manifest().Refs) != 0 {
		t.Fatalf("atomic batch with a failed ref committed refs anyway: %v", s.Manifest().Refs)
	}
}

func TestCallerGuardsRejectBadRepositories(t *testing.T) {
	vaultDir := t.TempDir()
	if _, err := vault.Create(vaultDir, "test-pass", crypto.Argon2Params{Algo: crypto.KDFAlgo, M: 16, T: 1, P: 1}); err != nil {
		t.Fatal(err)
	}

	// A sha256 repository must be refused before anything is stored.
	repo := t.TempDir()
	cmd := exec.Command("git", "init", "-q", "-b", "main", "--object-format=sha256", ".")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git lacks sha256 support: %v\n%s", err, out)
	}
	for _, args := range [][]string{
		{"config", "user.name", "T"},
		{"config", "user.email", "t@inv.alid"},
	} {
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.WriteFile(filepath.Join(repo, "f"), []byte("x\n"), 0o644)
	for _, args := range [][]string{{"add", "."}, {"commit", "-qm", "c"}} {
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	askpass := filepath.Join(t.TempDir(), "askpass")
	os.WriteFile(askpass, []byte("#!/bin/sh\necho test-pass\n"), 0o755)
	wdir, _ := os.Getwd()
	os.Chdir(repo)
	defer os.Chdir(wdir)
	oldAskpass := os.Getenv("GIT_ASKPASS")
	os.Setenv("GIT_ASKPASS", askpass)
	defer os.Setenv("GIT_ASKPASS", oldAskpass)

	err := Run(vaultDir, strings.NewReader("list for-push\npush HEAD:refs/heads/main\n\n"), &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("sha256 caller not refused: %v", err)
	}

	// A shallow repository must be refused for push (a plain sha1 source,
	// so the format guard does not fire first).
	plain := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main", "."},
		{"config", "user.name", "T"},
		{"config", "user.email", "t@inv.alid"},
	} {
		c := exec.Command("git", args...)
		c.Dir = plain
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, content := range []string{"one\n", "two\n"} {
		os.WriteFile(filepath.Join(plain, "f"), []byte(content), 0o644)
		for _, args := range [][]string{{"add", "."}, {"commit", "-qm", "c"}} {
			c := exec.Command("git", args...)
			c.Dir = plain
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
	}
	shallow := t.TempDir()
	clone := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+plain, shallow)
	if out, err := clone.CombinedOutput(); err != nil {
		t.Skipf("shallow clone failed: %v\n%s", err, out)
	}
	os.Chdir(shallow)
	err = Run(vaultDir, strings.NewReader("list for-push\npush HEAD:refs/heads/main\n\n"), &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "shallow") {
		t.Fatalf("shallow caller not refused: %v", err)
	}
}

func TestParseCredentialTrimsWindowsLineEndings(t *testing.T) {
	// A Windows askpass (.bat echo) or any CRLF-leaking layer must not
	// corrupt the passphrase: git itself normally strips \r, this guards
	// the layers that do not.
	got, err := parseCredential("protocol=coffer\r\nhost=coffer\r\npath=abc\r\nusername=coffer\r\npassword=1234test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1234test" {
		t.Fatalf("passphrase = %q, want 1234test (CR leaked in)", got)
	}
	if got, _ := parseCredential("password=\r\n"); got != "" {
		t.Fatalf("empty password with CR accepted: %q", got)
	}
}

// TestValuelessOptionProbe pins git 2.30's behavior: it sends
// "option object-format" with NO value as a support probe and treats a
// non-ok answer as fatal — every push died with 128 on that git until
// the probe form was accepted. Modern git sends values; the probe form
// only appears on the supported floor, so the golden suite cannot catch
// a regression here — this session-level test is the guard.
func TestValuelessOptionProbe(t *testing.T) {
	vaultDir := t.TempDir()
	if _, err := vault.Create(vaultDir, "test-pass", crypto.Argon2Params{Algo: crypto.KDFAlgo, M: 16, T: 1, P: 1}); err != nil {
		t.Fatal(err)
	}
	out := driveSession(t, t.TempDir(), vaultDir,
		"option object-format",
		"option progress",
		"option dry-run",
		"option atomic",
		"option no-such-option",
	)
	// Known options: probes answer ok. Unknown: unsupported.
	want := []string{"ok", "ok", "ok", "ok", "unsupported"}
	got := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			got = append(got, line)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("probe answers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("probe answer %d = %q, want %q", i, got[i], want[i])
		}
	}
}
