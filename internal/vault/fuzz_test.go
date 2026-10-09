package vault

// Fuzz seeds for the plaintext-header parser: vault.meta is the first
// untrusted file every operation reads. Seeds run on every `go test`;
// `go test -fuzz=FuzzReadMeta` explores further. The invariant: any byte
// sequence either parses as a valid header or errors — never panics.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzReadMeta(f *testing.F) {
	dir := f.TempDir()
	s, err := Create(dir, "fuzz-pass", weakParams())
	if err != nil {
		f.Fatal(err)
	}
	_ = s
	valid, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("{"))
	f.Add([]byte(`{"format_version":1}`))
	f.Add([]byte(`{"format_version":2,"id":"` + strings.Repeat("a", 32) + `","slots":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, metaName), data, 0o600); err != nil {
			t.Skip()
		}
		meta, err := ReadMeta(dir)
		if err == nil {
			// Whatever parsed must satisfy every documented invariant.
			if !isHexID(meta.ID) || len(meta.Slots) == 0 || len(meta.Slots) > maxKeySlots {
				t.Fatalf("parser accepted invalid header: %+v", meta)
			}
		}
	})
}
