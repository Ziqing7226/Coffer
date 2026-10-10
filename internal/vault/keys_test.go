package vault

// Phase 3 coverage: key-slot rotation, second-factor key files, gc, fsck.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ziqing7226/GitCoffer/internal/crypto"
)

// storeWithObject creates a vault with one committed, referenced object
// file, and returns the opened store plus the object's name.
func storeWithObject(t *testing.T, dir, pass string) (*Store, string) {
	t.Helper()
	s, err := Create(dir, pass, weakParams())
	if err != nil {
		t.Fatal(err)
	}
	name, err := s.WriteObject(strings.NewReader("pack-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifest()
	m.Packs[name] = PackInfo{
		SHA256:  crypto.Hash([]byte("pack-bytes")),
		Size:    int64(len("pack-bytes")),
		Objects: []string{strings.Repeat("a", 40)},
	}
	if err := s.Commit(m); err != nil {
		t.Fatal(err)
	}
	return s, name
}

func objBytes(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, objDirName, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRekeyRotatesOnlyMeta(t *testing.T) {
	dir := t.TempDir()
	s, name := storeWithObject(t, dir, "old-pass")
	before := objBytes(t, dir, name)

	if err := s.Rekey("new-pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "old-pass"); err == nil {
		t.Fatal("old passphrase still opens the vault after rekey")
	}
	s2, err := Open(dir, "new-pass")
	if err != nil {
		t.Fatalf("new passphrase rejected: %v", err)
	}
	if got := s2.OpenedSlotID(); got != 0 {
		t.Fatalf("rekey moved the slot: opened slot %d", got)
	}
	after := objBytes(t, dir, name)
	if string(before) != string(after) {
		t.Fatal("rekey touched object data — only vault.meta may change")
	}
	if len(s2.Meta().Slots) != 1 {
		t.Fatalf("rekey changed the slot count: %d", len(s2.Meta().Slots))
	}
}

func TestAddRemoveSlots(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass-a")

	id, err := s.AddSlot("pass-b", "")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("second slot id = %d, want 1", id)
	}
	for _, pass := range []string{"pass-a", "pass-b"} {
		if _, err := Open(dir, pass); err != nil {
			t.Fatalf("passphrase %q rejected after key add: %v", pass, err)
		}
	}

	if err := s.RemoveSlot(0); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "pass-a"); err == nil {
		t.Fatal("removed slot still opens the vault")
	}
	if _, err := Open(dir, "pass-b"); err != nil {
		t.Fatalf("remaining slot rejected: %v", err)
	}

	if err := s.RemoveSlot(1); err == nil || !strings.Contains(err.Error(), "last key slot") {
		t.Fatalf("removing the last slot not refused: %v", err)
	}
}

func TestKeyfileSecondFactor(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(t.TempDir(), "coffer.key")

	s, _ := storeWithObject(t, dir, "pass-a")
	if _, err := s.AddSlot("pass-b", keyfile); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(keyfile); err != nil || len(data) != 32 {
		t.Fatalf("key file not created with 32 random bytes: %v %d", err, len(data))
	}

	// The second-factor slot opens with passphrase + key file.
	if _, err := Open(dir, "pass-b"); err != nil {
		t.Fatalf("keyfile slot rejected with the key file present: %v", err)
	}
	// The passphrase-only slot still works.
	if _, err := Open(dir, "pass-a"); err != nil {
		t.Fatalf("passphrase slot rejected: %v", err)
	}

	// Remove the passphrase-only slot: the vault now requires the key file.
	if err := s.RemoveSlot(0); err != nil {
		t.Fatal(err)
	}
	os.Remove(keyfile)
	_, err := Open(dir, "pass-b")
	if err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("missing key file not named in the error: %v", err)
	}
}

func TestKeyfileMinimumEntropy(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass-a")

	// A near-empty existing key file would silently degenerate the second
	// factor to the passphrase alone; adding must refuse it.
	tiny := filepath.Join(t.TempDir(), "tiny.key")
	if err := os.WriteFile(tiny, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.AddSlot("pass-b", tiny)
	if err == nil || !strings.Contains(err.Error(), "real entropy") {
		t.Fatalf("tiny key file accepted: %v", err)
	}
	if len(s.Meta().Slots) != 1 {
		t.Fatalf("rejected add still changed the slot count: %d", len(s.Meta().Slots))
	}
}

func TestMetaOpsUseFreshState(t *testing.T) {
	dir := t.TempDir()
	s1, _ := storeWithObject(t, dir, "pass-a")
	s2, err := Open(dir, "pass-a")
	if err != nil {
		t.Fatal(err)
	}

	// s2 rotates the passphrase while s1 still holds its Open-time
	// snapshot; s1's later AddSlot must land on the FRESH slot set —
	// not overwrite it with the stale snapshot (which would silently
	// undo the rotation while reporting success).
	if err := s2.Rekey("pass-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.AddSlot("pass-c", ""); err != nil {
		t.Fatalf("add on a stale snapshot: %v", err)
	}
	if _, err := Open(dir, "pass-b"); err != nil {
		t.Fatalf("the concurrent rotation was silently undone: %v", err)
	}
	if _, err := Open(dir, "pass-c"); err != nil {
		t.Fatalf("the added slot does not open: %v", err)
	}

	// Rotate the slot that s2 opened (slot 0) — lands on fresh state.
	if err := s2.Rekey("pass-d"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "pass-d"); err != nil {
		t.Fatal(err)
	}
	// s1 removes the slot s1 itself opened (slot 0, now pass-d);
	// s1's rekey then targets a slot that no longer exists and must
	// fail cleanly — pinning the not-found refusal branch.
	if err := s1.RemoveSlot(0); err != nil {
		t.Fatal(err)
	}
	if err := s1.Rekey("pass-e"); err == nil ||
		!strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("rekey of a removed slot not refused: %v", err)
	}
	if _, err := Open(dir, "pass-c"); err != nil {
		t.Fatal(err)
	}
}

func TestAddSlotRefusesAtTheCap(t *testing.T) {
	dir := t.TempDir()
	s, _ := storeWithObject(t, dir, "pass-a")
	for i := 1; i < maxKeySlots; i++ {
		if _, err := s.AddSlot(fmt.Sprintf("pass-%d", i), ""); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if _, err := s.AddSlot("over-the-cap", ""); err == nil ||
		!strings.Contains(err.Error(), "maximum of 16 key slots") {
		t.Fatalf("slot cap not enforced: %v", err)
	}
	// The vault must remain fully readable at the cap.
	if _, err := Open(dir, "pass-a"); err != nil {
		t.Fatalf("vault unreadable at the slot cap: %v", err)
	}
}
