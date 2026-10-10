package main

// coffer doctor: a read-only health check for the environment and a
// vault — git and helper discoverability, meta shape, key-file presence,
// filesystem characteristics, leftover state. Failures exit non-zero;
// warnings do not.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/Ziqing7226/GitCoffer/internal/vault"
)

type diag struct {
	failed bool
}

func (d *diag) ok(format string, args ...any) {
	fmt.Printf("[ok]   "+format+"\n", args...)
}

func (d *diag) warn(format string, args ...any) {
	fmt.Printf("[warn] "+format+"\n", args...)
}

func (d *diag) fail(format string, args ...any) {
	d.failed = true
	fmt.Printf("[fail] "+format+"\n", args...)
}

func doctorCmd(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer doctor <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	dir := fs.Arg(0)
	d := &diag{}

	// Environment: git version and helper discoverability.
	if out, err := exec.Command("git", "--version").Output(); err != nil {
		d.fail("git not runnable on PATH (%v)", err)
	} else if v, ok := parseGitVersion(string(out)); !ok {
		d.warn("cannot parse git version %q", string(out))
	} else if v < 230 {
		d.fail("git %d.%d is older than the supported floor 2.30 (remote-helper object-format)", v/100, v%100)
	} else {
		d.ok("git %d.%d supports the remote-helper protocol", v/100, v%100)
	}
	if _, err := exec.LookPath("git-remote-coffer"); err != nil {
		d.fail("git-remote-coffer not found on PATH — pushes and clones cannot reach the vault")
	} else {
		d.ok("git-remote-coffer discoverable on PATH")
	}

	// Vault structure: no passphrase needed for these.
	meta, err := vault.ReadMeta(dir)
	switch {
	case errors.Is(err, vault.ErrNotVault):
		d.fail("%v", err)
	case err != nil:
		d.fail("vault.meta unreadable: %v", err)
	default:
		d.ok("vault.meta valid: format v%d, id %s, %d key slot(s)", meta.FormatVersion, meta.ID, len(meta.Slots))
		for _, sl := range meta.Slots {
			if sl.Input != "passphrase+keyfile" || sl.Keyfile == "" {
				continue
			}
			path := sanitizePath(sl.Keyfile)
			if !filepath.IsAbs(path) {
				path = filepath.Join(dir, path)
			}
			path = sanitizePath(path)
			info, serr := os.Lstat(path)
			switch {
			case serr != nil:
				d.warn("slot %d key file missing: %s (that slot cannot open until restored)", sl.ID, path)
			case !info.Mode().IsRegular():
				d.warn("slot %d key file is not a regular file: %s", sl.ID, path)
			default:
				d.ok("slot %d key file present: %s", sl.ID, path)
			}
		}
	}
	gens := vault.GenerationNums(dir)
	if len(gens) == 0 {
		d.fail("no manifest generations on disk")
	} else {
		d.ok("manifest generations on disk: %s", generationList(gens))
	}

	// Media and leftover state.
	if fsName, known := filesystemName(dir); known {
		switch {
		case fsName == "vfat" || fsName == "msdos" || fsName == "exfat":
			d.warn("filesystem %s caps single files at 2–4 GiB; a single object file larger than that cannot be written", fsName)
		default:
			d.ok("filesystem %s", fsName)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.lock")); err == nil {
		d.warn("a vault.lock is present — a write may be running, or a crashed one left it (auto-recovered after the staleness window)")
	}
	objDir := filepath.Join(dir, "obj")
	entries, err := os.ReadDir(objDir)
	switch {
	case err != nil:
		d.fail("object directory unreadable: %v", err)
	default:
		objs, tmps, bytes := 0, 0, int64(0)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) == ".tmp" {
				tmps++
				continue
			}
			objs++
			if info, ierr := e.Info(); ierr == nil {
				bytes += info.Size()
			}
		}
		d.ok("object files: %d (%s ciphertext)", objs, humanBytes(bytes))
		// Root-level temp leftovers (interrupted manifest writes) count
		// too — the same files gc sweeps.
		rootEntries, rerr := os.ReadDir(dir)
		if rerr == nil {
			for _, e := range rootEntries {
				if !e.IsDir() && filepath.Ext(e.Name()) == ".tmp" {
					tmps++
				}
			}
		}
		if tmps > 0 {
			d.warn("%d temp leftover(s) — gitcoffer gc removes them", tmps)
		}
	}

	if d.failed {
		return fmt.Errorf("doctor found problems")
	}
	fmt.Println("doctor complete: no failures")
	return nil
}

var gitVersionRe = regexp.MustCompile(`git version (\d+)\.(\d+)`)

func parseGitVersion(out string) (int, bool) {
	m := gitVersionRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return major*100 + minor, true
}
