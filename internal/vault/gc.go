package vault

// gc reclaims space without weakening guarantees: object files referenced
// by no manifest generation on disk (crashed or aborted pushes), leftover
// .tmp files, and manifest generations beyond the kept bound.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GCReport describes one gc pass.
type GCReport struct {
	RemovedObjects    []string
	RemovedTmp        []string
	PrunedGenerations []int
	BytesFreed        int64
}

// GC collects garbage from the vault at dir. It needs the passphrase
// because the reference set lives inside encrypted manifests; if any
// generation on disk fails to decrypt, GC refuses to delete anything —
// a broken vault must be repaired (fsck) before it is cleaned. GC holds
// the writer lock for the whole pass: without it, a concurrent push
// could commit an object between the scan and the sweep, and the sweep
// would delete the just-committed file.
func GC(dir, passphrase string) (*GCReport, error) {
	return gc(dir, passphrase, false)
}

// GCDryRun reports what GC would remove without deleting anything.
func GCDryRun(dir, passphrase string) (*GCReport, error) {
	return gc(dir, passphrase, true)
}

func gc(dir, passphrase string, dryRun bool) (*GCReport, error) {
	s, err := Open(dir, passphrase)
	if err != nil {
		return nil, err
	}
	release, err := s.AcquireLock()
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.Reload(); err != nil {
		return nil, err
	}
	rep := &GCReport{}

	// Reference set: every pack named by every generation on disk.
	referenced := map[string]bool{}
	for _, n := range manifestGenerations(dir) {
		m, _, err := s.readManifestNum(n)
		if err != nil {
			return nil, fmt.Errorf("generation %d unreadable: %v — gc refuses to delete anything; run gitcoffer fsck", n, err)
		}
		for name := range m.Packs {
			referenced[name] = true
		}
	}

	// Sweep obj/: unreferenced object files and .tmp leftovers.
	entries, err := os.ReadDir(filepath.Join(dir, objDirName))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			if dryRun {
				rep.RemovedTmp = append(rep.RemovedTmp, "obj/"+name)
				rep.BytesFreed += info.Size()
			} else if os.Remove(filepath.Join(dir, objDirName, name)) == nil {
				rep.RemovedTmp = append(rep.RemovedTmp, "obj/"+name)
				rep.BytesFreed += info.Size()
			}
			continue
		}
		if !referenced[name] {
			if dryRun {
				rep.RemovedObjects = append(rep.RemovedObjects, name)
				rep.BytesFreed += info.Size()
			} else if os.Remove(filepath.Join(dir, objDirName, name)) == nil {
				rep.RemovedObjects = append(rep.RemovedObjects, name)
				rep.BytesFreed += info.Size()
			}
		}
	}

	// Sweep .tmp leftovers in the vault root (manifest writes).
	rootEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range rootEntries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if dryRun {
			rep.RemovedTmp = append(rep.RemovedTmp, name)
			rep.BytesFreed += info.Size()
		} else if os.Remove(filepath.Join(dir, name)) == nil {
			rep.RemovedTmp = append(rep.RemovedTmp, name)
			rep.BytesFreed += info.Size()
		}
	}

	// Re-enforce the generation bound (commits already prune; a vault
	// assembled from copies may carry more).
	// Generation pruning: report what falls outside the kept bound. In
	// dry-run nothing is deleted — the report lists what a real pass
	// would prune.
	newest := s.manifestNum
	kept := s.manifest.Generations.Kept
	for _, n := range manifestGenerations(dir) {
		if n < newest-kept+1 {
			if !dryRun {
				os.Remove(filepath.Join(dir, fmt.Sprintf("%s%d", manifestPrefix, n)))
			}
			rep.PrunedGenerations = append(rep.PrunedGenerations, n)
		}
	}
	return rep, nil
}
