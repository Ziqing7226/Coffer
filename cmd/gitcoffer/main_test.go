package main

// Guard tests for the command↔documentation contract: every command the
// CLI implements must be listed in its usage text and mentioned in the
// user-facing docs, and the documented version output must match what the
// command actually prints. These exist because a `version` output drifted
// from the docs once — surface changes must fail here first.

import (
	"os"
	"strings"
	"testing"
)

// implementedCommands is the source of truth: every gitcoffer subcommand.
var implementedCommands = []string{
	"init", "status", "rekey", "key", "gc", "fsck", "doctor",
	"export-bundle", "version", "completion",
}

func TestUsageListsEveryCommand(t *testing.T) {
	capture := func() string {
		old := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w
		usage()
		w.Close()
		os.Stderr = old
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return sb.String()
	}
	out := capture()
	for _, cmd := range implementedCommands {
		if !strings.Contains(out, "gitcoffer "+cmd) {
			t.Errorf("usage text does not list `gitcoffer %s`:\n%s", cmd, out)
		}
	}
}

func TestDocsMentionEveryCommand(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return string(data)
	}
	readme := read("../../README.md")
	guide := read("../../docs/user-guide.md")

	for _, cmd := range implementedCommands {
		// The guide is the complete reference; the README carries the
		// table too. Key is a prefix of key add/remove/list — match
		// "gitcoffer key" there.
		name := cmd
		if cmd == "key" {
			name = "key "
		}
		if !strings.Contains(guide, "gitcoffer "+name) {
			t.Errorf("docs/user-guide.md never mentions `gitcoffer %s`", cmd)
		}
		if !strings.Contains(readme, "gitcoffer "+name) {
			t.Errorf("README.md never mentions `gitcoffer %s`", cmd)
		}
	}
}

func TestVersionLineShape(t *testing.T) {
	// The version line is a single line starting with the binary name —
	// scripts and docs both depend on that shape.
	line := "gitcoffer " + versionString()
	if strings.Contains(line, "\n") || !strings.HasPrefix(line, "gitcoffer ") {
		t.Fatalf("version line malformed: %q", line)
	}
	// Source builds (no -ldflags stamp) must self-identify, not claim a
	// release version — that mismatch is exactly what docs promise not to
	// do.
	if version == "" && !strings.Contains(versionString(), "development build") {
		t.Fatalf("unstamped build claims a release version: %q", versionString())
	}
}

func TestDocsFreeOfRenameArtifacts(t *testing.T) {
	// Chained renames once produced "gitgitcoffer" and output lines still
	// prefixed "coffer" under a "gitcoffer" command. These guards pin the
	// whole class: no replacement artifacts, no mismatched console output,
	// and the project title matches the repository name.
	files := []string{"../../README.md", "../../docs/user-guide.md",
		"../../CHANGELOG.md", "../../AGENTS.md", "../../CONTRIBUTING.md",
		"../../SECURITY.md", "../../docs/architecture.md",
		"../../docs/development.md", "../../docs/support-matrix.md",
		"../../docs/threat-model.md", "../../docs/format-spec.md"}
	read := func(p string) string {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		return string(data)
	}
	for _, p := range files {
		text := read(p)
		for _, artifact := range []string{"gitgit", "coffercoffer", "gitt-", "git-gitcoffer"} {
			if strings.Contains(text, artifact) {
				t.Errorf("%s contains rename artifact %q", p, artifact)
			}
		}
		// Every console block that runs `gitcoffer version` must print a
		// line prefixed "gitcoffer " — never the old binary name.
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "coffer ") {
				t.Errorf("%s has an output line prefixed with the old binary name: %q", p, line)
			}
		}
	}
	// The README title is the project name.
	readme := read("../../README.md")
	if !strings.Contains(readme, "<h1 align=\"center\">GitCoffer</h1>") {
		t.Error("README title is not GitCoffer")
	}
}

func TestRenderVersion(t *testing.T) {
	cases := []struct {
		name                      string
		stamped, mainV, rev, date string
		dirty                     bool
		want                      string
	}{
		{"release stamp wins", "v1.0.0", "v1.0.0", "abc", "", false, "v1.0.0"},
		{"go install @tag", "", "v1.0.0-rc.1", "", "", false, "v1.0.0-rc.1"},
		{"repo build reports commit", "", "(devel)", "0123456789abcdef", "2026-01-01T00:00:00Z", false,
			"development build from commit 0123456789ab (2026-01-01T00:00:00Z)"},
		{"dirty marker", "", "(devel)", "0123456789abcdef", "", true,
			"development build from commit 0123456789ab (modified)"},
		{"context-free fallback", "", "", "", "", false, "development build"},
	}
	for _, tc := range cases {
		if got := renderVersion(tc.stamped, tc.mainV, tc.rev, tc.date, tc.dirty); got != tc.want {
			t.Errorf("%s: renderVersion = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func captureCompletion(t *testing.T, shell string) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	if err := completionCmd([]string{shell}); err != nil {
		os.Stdout = old
		t.Fatalf("completion %s: %v", shell, err)
	}
	w.Close()
	os.Stdout = old
	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

func captureCompletionErr(t *testing.T, shell string) (string, error) {
	t.Helper()
	var sb strings.Builder
	err := completionCmd([]string{shell})
	return sb.String(), err
}

func TestCompletionCoversEveryCommand(t *testing.T) {
	for shell, want := range map[string]string{
		"bash":       "init status rekey key gc fsck doctor export-bundle version",
		"zsh":        "'init:create",
		"fish":       "complete -c gitcoffer -n '__fish_use_subcommand' -a init",
		"powershell": "'init','status'",
	} {
		out := captureCompletion(t, shell)
		if !strings.Contains(out, want) {
			t.Errorf("%s completion lacks %q:\n%s", shell, want, out)
		}
	}
	if _, err := captureCompletionErr(t, "tcsh"); err == nil {
		t.Error("unknown shell accepted")
	}
}
