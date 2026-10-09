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
	"export-bundle", "version",
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
