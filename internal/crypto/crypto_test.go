package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func weakParams() Argon2Params {
	return Argon2Params{Algo: KDFAlgo, M: 16, T: 1, P: 1, Salt: bytes.Repeat([]byte{7}, MinSaltSize)}
}

func TestSlotRoundTrip(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	slot, err := SealSlot(0, "correct horse battery", dek, "aabbccdd", weakParams())
	if err != nil {
		t.Fatal(err)
	}
	got, err := slot.Open("correct horse battery", "aabbccdd")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("DEK mismatch after round trip")
	}

	if _, err := slot.Open("wrong passphrase", "aabbccdd"); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong passphrase: want ErrAuth, got %v", err)
	}
	if _, err := slot.Open("correct horse battery", "othervault"); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong vault AAD: want ErrAuth, got %v", err)
	}
	slot.DEK[3] ^= 0xff
	if _, err := slot.Open("correct horse battery", "aabbccdd"); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered slot: want ErrAuth, got %v", err)
	}
}

func TestDefaultParamsAreStrong(t *testing.T) {
	p := DefaultParams()
	if p.M < 64*1024 || p.T < 3 || p.P < 4 {
		t.Fatalf("defaults below spec recommendation: %+v", p)
	}
	if p.Algo != KDFAlgo {
		t.Fatal("default kdf algo")
	}
}

// TestOpenNeverPanicsOnMalformedSlot guards the "precise error, never a
// panic" exit criterion: a corrupted vault.meta must not crash the helper.
func TestOpenNeverPanicsOnMalformedSlot(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	slot, err := SealSlot(0, "pw", dek, "vault", weakParams())
	if err != nil {
		t.Fatal(err)
	}

	check := func(name string, mutate func(*Slot)) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s: panicked instead of erroring: %v", name, r)
			}
		}()
		bad := *slot
		mutate(&bad)
		if _, err := bad.Open("pw", "vault"); err == nil {
			t.Fatalf("%s: malformed slot accepted", name)
		}
	}

	check("truncated nonce", func(s *Slot) { s.AEAD.Nonce = s.AEAD.Nonce[:10] })
	check("oversized nonce", func(s *Slot) { s.AEAD.Nonce = append(append([]byte{}, s.AEAD.Nonce...), 0) })
	check("parallelism wraps uint8", func(s *Slot) { s.KDF.P = 256 })
	check("zero parallelism", func(s *Slot) { s.KDF.P = 0 })
	check("memory below argon2 minimum", func(s *Slot) { s.KDF.M = 8; s.KDF.P = 4 })
}

func TestParamBoundsEnforced(t *testing.T) {
	goodSalt := make([]byte, SaltSize)
	for _, p := range []Argon2Params{
		{Algo: KDFAlgo, M: 64 * 1024, T: 3, P: 256, Salt: goodSalt},               // parallelism over ceiling
		{Algo: KDFAlgo, M: 64 * 1024, T: 3, P: 1 << 20, Salt: goodSalt},           // absurd parallelism
		{Algo: KDFAlgo, M: 8 << 20, T: 3, P: 4, Salt: goodSalt},                   // memory over ceiling (8 GiB)
		{Algo: KDFAlgo, M: 64 * 1024, T: 1 << 20, P: 4, Salt: goodSalt},           // time over ceiling
		{Algo: KDFAlgo, M: 64 * 1024, T: 3, P: 4, Salt: goodSalt[:MinSaltSize-1]}, // salt too short
	} {
		if err := p.validate(); err == nil {
			t.Fatalf("unsafe params accepted: %+v", p)
		}
	}
	for _, p := range []Argon2Params{DefaultParams(), weakParams()} {
		if err := p.validate(); err != nil {
			t.Fatalf("legitimate params rejected: %+v: %v", p, err)
		}
	}
}

func TestManifestSealOpen(t *testing.T) {
	dek, _ := NewDEK()
	payload := []byte(strings.Repeat("manifest payload ", 32))
	rec, err := SealManifest(dek, "vault1", payload)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := OpenManifest(dek, "vault1", rec)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatal("payload mismatch")
	}
	if _, err := OpenManifest(dek, "vault2", rec); !errors.Is(err, ErrAuth) {
		t.Fatalf("cross-vault replay: want ErrAuth, got %v", err)
	}
	rec[len(rec)-1] ^= 0x01
	if _, err := OpenManifest(dek, "vault1", rec); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered manifest: want ErrAuth, got %v", err)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	sizes := []int64{1, 100, 4096}
	if !testing.Short() {
		sizes = append(sizes, ChunkSize+1000) // multi-chunk, >64 MiB
	}
	dek, _ := NewDEK()
	specific := func(k int) string { return "vault/objname/" + itoa(k) }
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i * 31)
		}
		var enc bytes.Buffer
		if err := WriteChunked(&enc, bytes.NewReader(data), dek, specific); err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		rd, err := ReadChunked(bytes.NewReader(enc.Bytes()), size, dek, specific)
		if err != nil {
			t.Fatalf("size %d: reader: %v", size, err)
		}
		got, err := io.ReadAll(rd)
		if err != nil {
			t.Fatalf("size %d: read: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestChunkTamperDetected(t *testing.T) {
	dek, _ := NewDEK()
	data := bytes.Repeat([]byte{0xab}, 4096)
	specific := func(k int) string { return "v/o/" + itoa(k) }
	var enc bytes.Buffer
	if err := WriteChunked(&enc, bytes.NewReader(data), dek, specific); err != nil {
		t.Fatal(err)
	}
	raw := enc.Bytes()
	raw[len(raw)/2] ^= 0x40 // flip a ciphertext byte
	rd, err := ReadChunked(bytes.NewReader(raw), int64(len(data)), dek, specific)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(rd)
	if err == nil {
		t.Fatal("tampered chunk decrypted without error")
	}
	if !strings.Contains(err.Error(), "chunk 0") || !errors.Is(err, ErrAuth) {
		t.Fatalf("error lacks chunk context / ErrAuth: %v", err)
	}
}

func TestChunkTruncated(t *testing.T) {
	dek, _ := NewDEK()
	specific := func(k int) string { return "v/o/" + itoa(k) }
	var enc bytes.Buffer
	if err := WriteChunked(&enc, bytes.NewReader(bytes.Repeat([]byte{1}, 500)), dek, specific); err != nil {
		t.Fatal(err)
	}
	rd, _ := ReadChunked(bytes.NewReader(enc.Bytes()[:20]), 500, dek, specific)
	if _, err := io.ReadAll(rd); err == nil {
		t.Fatal("truncated stream read without error")
	}
}

func itoa(k int) string {
	if k == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for k > 0 {
		i--
		b[i] = byte('0' + k%10)
		k /= 10
	}
	return string(b[i:])
}
