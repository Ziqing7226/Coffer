package crypto

// Format conformance vectors (docs/format-spec.md §8): docs/test-vectors.json
// pins the key-slot envelope, the manifest record, and object-chunk framing
// with fixed inputs. The verification test re-derives every expected byte
// through the production code paths (with the nonce injection points) and
// round-trips what they seal — any accidental drift in the format fails
// here. Regenerate the file with:
//
//	COFFER_WRITE_VECTORS=1 go test ./internal/crypto -run TestWriteFormatVectors

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type vectorFile struct {
	FormatVersion int    `json:"format_version"`
	VaultID       string `json:"vault_id"`
	Passphrase    string `json:"passphrase"`
	DEK           string `json:"dek"` // 64 hex
	Argon2        struct {
		M    int    `json:"m"`
		T    int    `json:"t"`
		P    int    `json:"p"`
		Salt string `json:"salt"` // b64
	} `json:"argon2"`
	Slot struct {
		SlotID         int    `json:"slot_id"`
		Nonce          string `json:"nonce"`           // b64, 24 bytes
		ExpectedSealed string `json:"expected_sealed"` // b64: the slot's dek field
	} `json:"meta_slot"`
	Manifest struct {
		Nonce          string `json:"nonce"`
		Payload        string `json:"payload"` // plaintext, UTF-8
		ExpectedRecord string `json:"expected_record"`
	} `json:"manifest"`
	Chunk struct {
		File      string `json:"file"` // 32 hex chars
		Chunk     int    `json:"chunk"`
		Nonce     string `json:"nonce"`
		Plaintext string `json:"plaintext"`
		Expected  string `json:"expected"`
	} `json:"obj_chunk"`
}

// Fixed vector inputs. Anything here is public and carries no secret.
const (
	vecVaultID    = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	vecPassphrase = "correct horse battery staple"
	vecDEKHex     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecSaltB64    = "AAECAwQFBgcICQoLDA0ODw=="         // 00..0f
	vecSlotNonce  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 24 bytes
	vecManNonce   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
	vecChunkNonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC"
	vecFile       = "deadbeefdeadbeefdeadbeefdeadbeef"
	vecChunkPT    = "coffer format v1 test vector payload\n"
)

func vectorDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := hex.DecodeString(vecDEKHex)
	if err != nil {
		t.Fatal(err)
	}
	return dek
}

func vecParams() Argon2Params {
	salt, _ := base64.StdEncoding.DecodeString(vecSaltB64)
	return Argon2Params{Algo: KDFAlgo, M: 65536, T: 3, P: 4, Salt: salt}
}

func b64Equal(t *testing.T, what, got, want string) {
	t.Helper()
	g, _ := base64.StdEncoding.DecodeString(got)
	w, _ := base64.StdEncoding.DecodeString(want)
	if !bytes.Equal(g, w) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", what, g, w)
	}
}

func TestFormatVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "test-vectors.json"))
	if err != nil {
		t.Fatalf("reading vectors (regenerate with COFFER_WRITE_VECTORS=1): %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.FormatVersion != FormatVersion {
		t.Fatalf("vector file is for format version %d, this build implements %d", v.FormatVersion, FormatVersion)
	}
	if v.VaultID != vecVaultID || v.Passphrase != vecPassphrase || v.DEK != vecDEKHex {
		t.Fatal("vector file inputs drifted from the pinned constants")
	}
	if v.Argon2.M != 65536 || v.Argon2.T != 3 || v.Argon2.P != 4 || v.Argon2.Salt != vecSaltB64 {
		t.Fatalf("vector file argon2 block drifted from the pinned parameters: %+v", v.Argon2)
	}
	salt, _ := base64.StdEncoding.DecodeString(v.Argon2.Salt)
	params := Argon2Params{Algo: KDFAlgo, M: uint32(v.Argon2.M), T: uint32(v.Argon2.T), P: uint32(v.Argon2.P), Salt: salt}

	// Key-slot envelope: exact bytes plus a round-trip open, deriving
	// under the parameters as published in the file.
	nonce, _ := base64.StdEncoding.DecodeString(v.Slot.Nonce)
	slot, err := sealSlot(v.Slot.SlotID, v.Passphrase, vectorDEK(t), v.VaultID, params, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(slot.DEK); got != v.Slot.ExpectedSealed {
		t.Fatalf("sealed DEK mismatch:\n got %s\nwant %s", got, v.Slot.ExpectedSealed)
	}
	if _, err := slot.Open(v.Passphrase, v.VaultID); err != nil {
		t.Fatalf("vector slot does not open: %v", err)
	}

	// Manifest record: nonce || ciphertext, exact bytes plus open.
	mNonce, _ := base64.StdEncoding.DecodeString(v.Manifest.Nonce)
	record, err := sealManifest(vectorDEK(t), v.VaultID, []byte(v.Manifest.Payload), mNonce)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(record); got != v.Manifest.ExpectedRecord {
		t.Fatalf("manifest record mismatch:\n got %s\nwant %s", got, v.Manifest.ExpectedRecord)
	}
	if _, err := OpenManifest(vectorDEK(t), v.VaultID, record); err != nil {
		t.Fatalf("vector manifest does not open: %v", err)
	}

	// Object chunk framing: single chunk through the production writer.
	cNonce, _ := base64.StdEncoding.DecodeString(v.Chunk.Nonce)
	var buf bytes.Buffer
	specific := func(k int) string { return v.VaultID + "/" + v.Chunk.File + "/" + strconv.Itoa(k) }
	if err := writeChunked(&buf, strings.NewReader(v.Chunk.Plaintext), vectorDEK(t), specific,
		map[int][]byte{v.Chunk.Chunk: cNonce}); err != nil {
		t.Fatal(err)
	}
	b64Equal(t, "chunk bytes", base64.StdEncoding.EncodeToString(buf.Bytes()), v.Chunk.Expected)
}

func TestWriteFormatVectors(t *testing.T) {
	if os.Getenv("COFFER_WRITE_VECTORS") != "1" {
		t.Skip("set COFFER_WRITE_VECTORS=1 to regenerate docs/test-vectors.json")
	}
	slotNonce, _ := base64.StdEncoding.DecodeString(vecSlotNonce)
	slot, err := sealSlot(0, vecPassphrase, vectorDEK(t), vecVaultID, vecParams(), slotNonce)
	if err != nil {
		t.Fatal(err)
	}
	mNonce, _ := base64.StdEncoding.DecodeString(vecManNonce)
	record, err := sealManifest(vectorDEK(t), vecVaultID, []byte(`{"version":1,"refs":{}}`), mNonce)
	if err != nil {
		t.Fatal(err)
	}
	cNonce, _ := base64.StdEncoding.DecodeString(vecChunkNonce)
	var buf bytes.Buffer
	specific := func(k int) string { return vecVaultID + "/" + vecFile + "/" + strconv.Itoa(k) }
	if err := writeChunked(&buf, strings.NewReader(vecChunkPT), vectorDEK(t), specific,
		map[int][]byte{0: cNonce}); err != nil {
		t.Fatal(err)
	}

	v := vectorFile{FormatVersion: FormatVersion, VaultID: vecVaultID, Passphrase: vecPassphrase, DEK: vecDEKHex}
	v.Argon2.M, v.Argon2.T, v.Argon2.P, v.Argon2.Salt = 65536, 3, 4, vecSaltB64
	v.Slot.SlotID, v.Slot.Nonce = 0, vecSlotNonce
	v.Slot.ExpectedSealed = base64.StdEncoding.EncodeToString(slot.DEK)
	v.Manifest.Nonce = vecManNonce
	v.Manifest.Payload = `{"version":1,"refs":{}}`
	v.Manifest.ExpectedRecord = base64.StdEncoding.EncodeToString(record)
	v.Chunk.File, v.Chunk.Chunk, v.Chunk.Nonce = vecFile, 0, vecChunkNonce
	v.Chunk.Plaintext = vecChunkPT
	v.Chunk.Expected = base64.StdEncoding.EncodeToString(buf.Bytes())

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "test-vectors.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
