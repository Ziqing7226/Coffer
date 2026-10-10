package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Ziqing7226/GitCoffer/internal/bundle"
)

// exportBundleCmd exports a vault as a standard git bundle: the
// guaranteed exit path back to plain git, readable with no Coffer
// installed.
func exportBundleCmd(args []string) error {
	fs := flag.NewFlagSet("export-bundle", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer export-bundle <vault-directory> <output.bundle>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	dir, out := fs.Arg(0), fs.Arg(1)
	// The bundle is written by git running inside a scratch repository:
	// resolve the target against the caller's working directory first, or
	// a relative path silently lands in the (deleted) scratch dir.
	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absOut); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s", out)
	}

	pass, err := promptPassword("Passphrase")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Exporting: decrypting the vault into a plain git bundle (the output file is unencrypted — store it accordingly)")
	refs, err := bundle.Export(dir, pass, absOut)
	if err != nil {
		return err
	}
	fmt.Printf("Bundle written: %s (%d ref(s)) — readable by stock git: git clone %s\n", absOut, refs, absOut)
	return nil
}
