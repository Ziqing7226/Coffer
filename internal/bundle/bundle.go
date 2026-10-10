// Package bundle exports a vault as a plain, unencrypted git bundle —
// the guaranteed exit path: users can leave Coffer at any time with
// nothing but stock git.
package bundle

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Ziqing7226/GitCoffer/internal/packproc"
	"github.com/Ziqing7226/GitCoffer/internal/vault"
)

// Export decrypts the vault at vaultDir into a scratch repository and
// writes a standard git bundle containing every ref to outFile. The
// bundle is readable by stock git (`git clone <file.bundle>`,
// `git bundle verify`); it contains plaintext, so treat the file itself
// as sensitive. Returns the number of refs bundled.
func Export(vaultDir, passphrase, outFile string) (int, error) {
	s, err := vault.Open(vaultDir, passphrase)
	if err != nil {
		return 0, err
	}
	// The exit path must not hand the user an unverified older state
	// when the newest manifest generation is damaged.
	if f := s.FallbackFromGeneration(); f > 0 {
		return 0, fmt.Errorf(
			"the newest manifest generation %d is unreadable and an older state is being served — run gitcoffer fsck before exporting", f)
	}
	m := s.Manifest()

	repo, cleanup, err := packproc.TempBareRepo()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	// Decrypt every stored pack into the scratch repository — the same
	// revival the fetch path performs.
	packDir := filepath.Join(repo, "objects", "pack")
	names := make([]string, 0, len(m.Packs))
	for name := range m.Packs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rd, err := s.ReadObject(name)
		if err != nil {
			return 0, err
		}
		dst := filepath.Join(packDir, "pack-"+name+".pack")
		err = writeAllAndClose(rd, dst)
		if err != nil {
			return 0, err
		}
		if err := packproc.IndexPackInDir(repo, dst); err != nil {
			return 0, err
		}
	}

	// Recreate every ref, then a HEAD by the advertised fallback rule so
	// clones from the bundle check out like clones from the vault.
	if len(m.Refs) == 0 {
		return 0, fmt.Errorf("the vault holds no refs to export")
	}
	refNames := make([]string, 0, len(m.Refs))
	for name := range m.Refs {
		refNames = append(refNames, name)
	}
	sort.Strings(refNames)
	for _, name := range refNames {
		if err := packproc.RunIn(repo, "update-ref", name, m.Refs[name].OID); err != nil {
			return 0, fmt.Errorf("restoring %s: %v", name, err)
		}
	}
	head := ""
	for _, name := range refNames {
		if name == "refs/heads/main" || name == "refs/heads/master" {
			head = name
			break
		}
	}
	if head == "" {
		for _, name := range refNames {
			if len(name) > len("refs/heads/") && name[:len("refs/heads/")] == "refs/heads/" {
				head = name
				break
			}
		}
	}
	if head != "" {
		if err := packproc.RunIn(repo, "symbolic-ref", "HEAD", head); err != nil {
			return 0, err
		}
	}

	if err := packproc.RunIn(repo, "bundle", "create", outFile, "--all"); err != nil {
		return 0, fmt.Errorf("git bundle create: %v", err)
	}
	return len(refNames), nil
}

func writeAllAndClose(rd io.ReadCloser, dst string) error {
	defer rd.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, werr := io.Copy(f, rd)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
