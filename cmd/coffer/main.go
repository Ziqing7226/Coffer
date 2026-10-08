// Command coffer manages vaults: init creates one, status inspects it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ziqing7226/Coffer/internal/crypto"
	"github.com/Ziqing7226/Coffer/internal/vault"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCmd(os.Args[2:])
	case "status":
		err = statusCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "coffer: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "coffer: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  coffer init <vault-directory>     create a new encrypted vault
  coffer status <vault-directory>   inspect a vault (refs need the passphrase)
`)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: coffer init <vault-directory>")
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
	if _, err := os.Stat(filepath.Join(dir, "vault.meta")); err == nil {
		return fmt.Errorf("refusing to overwrite existing vault at %s", dir)
	}

	fmt.Fprintln(os.Stderr, "Enter passphrase for the new vault:")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Repeat passphrase:")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if len(first) == 0 {
		return errors.New("passphrase must not be empty")
	}
	if string(first) != string(second) {
		return errors.New("passphrases do not match")
	}

	s, err := vault.Create(dir, string(first), crypto.DefaultParams())
	if err != nil {
		return err
	}
	fmt.Printf("Vault created: %s\n  id: %s\n  format: v%d\n  key slots: %d\n",
		dir, s.Meta().ID, crypto.FormatVersion, len(s.Meta().Slots))
	return nil
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: coffer status <vault-directory>")
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

	meta, err := vault.ReadMeta(dir)
	if err != nil {
		return err
	}
	fmt.Printf("vault: %s\n  format: v%d\n  id: %s\n  created: %s\n  key slots: %d\n",
		dir, meta.FormatVersion, meta.ID, meta.Created.Format("2006-01-02 15:04:05 MST"), len(meta.Slots))
	fmt.Printf("  manifest generations on disk: %s\n", generationList(vault.GenerationNums(dir)))

	fmt.Fprintln(os.Stderr, "Passphrase:")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	s, err := vault.Open(dir, string(pass))
	if err != nil {
		return err
	}
	m := s.Manifest()
	names := make([]string, 0, len(m.Refs))
	for name := range m.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("  current generation: %d\n  refs (%d):\n", s.ManifestNum(), len(names))
	for _, name := range names {
		fmt.Printf("    %s %s\n", m.Refs[name].OID, name)
	}
	var objects, bytesStored int64
	for _, pack := range m.Packs {
		objects += int64(len(pack.Objects))
		bytesStored += pack.Size
	}
	fmt.Printf("  packs: %d (objects listed: %d, plaintext %s)\n",
		len(m.Packs), objects, humanBytes(bytesStored))
	return nil
}

func generationList(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
