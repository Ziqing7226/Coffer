package vault

// Key-slot management (spec §3): opening assembles each slot's KDF input
// (passphrase, or passphrase plus key-file bytes for second-factor slots),
// and key rotation rewrites only vault.meta — the DEK and every object
// file stay untouched.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ziqing7226/GitCoffer/internal/crypto"
)

// slotSecret assembles the KDF input for one slot. A relative key-file
// path resolves against the vault directory — never the caller's working
// directory, which for the remote helper is the pushing repository.
func slotSecret(dir string, slot crypto.Slot, passphrase string) (string, error) {
	switch slot.Input {
	case "", crypto.InputPassphrase:
		return passphrase, nil
	case crypto.InputPassphraseKeyfile:
		if slot.Keyfile == "" {
			return "", fmt.Errorf("slot %d requires a key file but none is configured", slot.ID)
		}
		path := slot.Keyfile
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		// The path comes from plaintext vault.meta an attacker may have
		// rewritten: refuse non-regular files (a device or FIFO would
		// read forever) and bound the size.
		data, err := readLimited(path, 1<<20)
		if err != nil {
			return "", fmt.Errorf("key file for slot %d: %v", slot.ID, sanitizePath(err.Error()))
		}
		return passphrase + string(data), nil
	default:
		// Unknown input type: a future format this build cannot use.
		return "", fmt.Errorf("slot %d: unsupported input %q", slot.ID, slot.Input)
	}
}

// sanitizePath strips control characters (including terminal escape
// sequences) from a path that originated in vault.meta before it is
// printed or embedded in an error hint.
func sanitizePath(p string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
}

// refreshMeta re-reads vault.meta into the store. Meta operations call
// it under the writer lock: the lock serializes, but the in-memory meta
// is the snapshot from Open — without the refresh, a concurrent key
// operation that landed in between would be silently overwritten by our
// stale copy (a rekey reported as successful could be undone).
func (s *Store) refreshMeta() error {
	meta, err := ReadMeta(s.dir)
	if err != nil {
		return err
	}
	s.meta = meta
	return nil
}

// rewriteMeta atomically replaces vault.meta (spec §6, pattern 3).
func (s *Store) rewriteMeta() error {
	data, err := json.MarshalIndent(s.meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.dir, metaName, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// OpenedSlotID returns the id of the key slot the current passphrase
// authenticated against.
func (s *Store) OpenedSlotID() int { return s.openedSlotID }

// AddSlot seals the vault's DEK under an additional passphrase, optionally
// combined with a key file (second factor). A keyfile path that does not
// yet exist is created with fresh random bytes, mode 0600, and its
// absolute path is recorded in the slot; the user must back it up
// separately from the vault. Returns the new slot id. Meta rewrites hold
// the writer lock so concurrent key operations refuse rather than race.
func (s *Store) AddSlot(newPass, keyfile string) (int, error) {
	release, err := s.AcquireLock()
	if err != nil {
		return 0, err
	}
	defer release()
	if err := s.refreshMeta(); err != nil {
		return 0, err
	}
	if len(s.meta.Slots) >= maxKeySlots {
		return 0, fmt.Errorf("the vault already has the maximum of %d key slots", maxKeySlots)
	}
	id := 0
	for _, sl := range s.meta.Slots {
		if sl.ID >= id {
			id = sl.ID + 1
		}
	}
	secret := newPass
	var created *crypto.Slot
	if keyfile != "" {
		keyfile, err = ensureKeyfile(keyfile)
		if err != nil {
			return 0, err
		}
		data, err := readLimited(keyfile, 1<<20)
		if err != nil {
			return 0, err
		}
		secret = newPass + string(data)
		created, err = crypto.SealSlot(id, secret, s.dek, s.meta.ID, crypto.DefaultParams())
		if err == nil {
			created.Input = crypto.InputPassphraseKeyfile
			created.Keyfile = keyfile
		}
	} else {
		created, err = crypto.SealSlot(id, secret, s.dek, s.meta.ID, crypto.DefaultParams())
	}
	if err != nil {
		return 0, err
	}
	s.meta.Slots = append(s.meta.Slots, *created)
	if err := s.rewriteMeta(); err != nil {
		return 0, err
	}
	return id, nil
}

// minKeyfileSize is the smallest existing file accepted as a key file: an
// empty or tiny file would make the "second factor" vacuous (the KDF input
// would degenerate to the passphrase alone) without any warning.
const minKeyfileSize = 16

// ensureKeyfile makes the key file exist: an existing file is used as-is
// (users may point at a file they manage), provided it carries real
// entropy; a missing one is created with 32 random bytes. The returned
// path is absolute.
func ensureKeyfile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(abs); err == nil {
		if info.Size() < minKeyfileSize {
			return "", fmt.Errorf("key file %s holds only %d bytes — a second factor must carry real entropy (at least %d bytes)", abs, info.Size(), minKeyfileSize)
		}
		return abs, nil
	}
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	// O_EXCL: if the file appears between the stat and the create
	// (restore job, sync tool), use the arrived file instead of
	// clobbering it with fresh random bytes the slot would then be
	// sealed to.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if info, serr := os.Stat(abs); serr == nil && info.Size() >= minKeyfileSize {
			return abs, nil
		}
		return "", err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return abs, nil
}

// RemoveSlot drops the slot with the given id from vault.meta. The last
// remaining slot is refused: a vault must keep at least one way in.
func (s *Store) RemoveSlot(id int) error {
	release, err := s.AcquireLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.refreshMeta(); err != nil {
		return err
	}
	if len(s.meta.Slots) <= 1 {
		return errors.New("refusing to remove the last key slot")
	}
	kept := s.meta.Slots[:0]
	found := false
	for _, sl := range s.meta.Slots {
		if sl.ID == id {
			found = true
			continue
		}
		kept = append(kept, sl)
	}
	if !found {
		return fmt.Errorf("no key slot with id %d", id)
	}
	s.meta.Slots = kept
	return s.rewriteMeta()
}

// Rekey re-seals the DEK under newPass in the slot the current passphrase
// opened, with a fresh salt, nonce, and default parameters. Only
// vault.meta is rewritten: object data is never re-encrypted (the DEK
// itself does not change).
func (s *Store) Rekey(newPass string) error {
	release, err := s.AcquireLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.refreshMeta(); err != nil {
		return err
	}
	fresh, err := crypto.SealSlot(s.openedSlotID, newPass, s.dek, s.meta.ID, crypto.DefaultParams())
	if err != nil {
		return err
	}
	found := false
	for i, sl := range s.meta.Slots {
		if sl.ID == s.openedSlotID {
			s.meta.Slots[i] = *fresh
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("the key slot this session opened (slot %d) no longer exists — another operation changed the vault's keys; re-open and try again", s.openedSlotID)
	}
	return s.rewriteMeta()
}
