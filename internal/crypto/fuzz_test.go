package crypto

// Fuzz seeds for the untrusted-input parsers: `go test` executes the seed
// corpus on every run, and `go test -fuzz=FuzzX` explores further. The
// invariant everywhere: malformed input errors, it never panics and never
// hangs.

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"
)

func FuzzOpenManifest(f *testing.F) {
	dek, err := RandomBytes(DEKSize)
	if err != nil {
		f.Fatal(err)
	}
	record, err := SealManifest(dek, "fuzz-vault", []byte(`{"version":1}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(record)
	f.Add([]byte{})
	f.Add([]byte("short"))
	f.Add(bytes.Repeat([]byte{0}, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := OpenManifest(dek, "fuzz-vault", data)
		if err == nil && string(payload) != `{"version":1}` {
			t.Fatalf("unexpected plaintext from fuzzed manifest: %q", payload)
		}
	})
}

func FuzzReadChunked(f *testing.F) {
	dek, err := RandomBytes(DEKSize)
	if err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	specific := func(k int) string { return "fuzz-vault/fuzz-file/" + strconv.Itoa(k) }
	if err := WriteChunked(&buf, strings.NewReader("fuzz plaintext"), dek, specific); err != nil {
		f.Fatal(err)
	}
	frame := buf.Bytes()
	f.Add(frame, int64(len("fuzz plaintext")))
	f.Add(frame[:len(frame)/2], int64(len("fuzz plaintext")))
	f.Add([]byte{}, int64(11))
	f.Add(bytes.Repeat([]byte{0xff}, 64), int64(1024))
	f.Fuzz(func(t *testing.T, data []byte, size int64) {
		if size < 0 || size > 1<<20 {
			size = 16
		}
		rd, err := ReadChunked(bytes.NewReader(data), size, dek, specific)
		if err != nil {
			return
		}
		// Drain with a bound: a framing bug that loops forever must
		// surface as a test timeout here, not in production.
		n, _ := io.CopyN(io.Discard, rd, 1<<20)
		_ = n
	})
}
