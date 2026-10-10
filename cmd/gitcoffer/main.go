// Command gitcoffer manages vaults: init creates one, status inspects it.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/Ziqing7226/GitCoffer/internal/crypto"
	"github.com/Ziqing7226/GitCoffer/internal/vault"
	"golang.org/x/term"
)

// version is stamped at release time via -ldflags "-X main.version=…".
// Source builds fall back to the VCS information the Go toolchain embeds
// (revision and commit time), so a self-built binary identifies exactly
// what it was built from instead of a generic placeholder.
var version = ""

// versionString renders the version line: the stamped release version,
// or the embedded VCS revision for source builds.
func versionString() string {
	info, _ := debug.ReadBuildInfo()
	var rev, commitDate, mainVersion string
	dirty := false
	if info != nil {
		mainVersion = info.Main.Version
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				commitDate = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	return renderVersion(version, mainVersion, rev, commitDate, dirty)
}

// renderVersion is the pure decision table behind `gitcoffer version`:
//   - release archives carry the -ldflags stamp;
//   - `go install …@vX` builds carry the module version in BuildInfo;
//   - a plain build inside the repository reports the commit it was
//     built from;
//   - only a context-free build falls back to the generic note.
func renderVersion(stamped, mainVersion, rev, commitDate string, dirty bool) string {
	if stamped != "" {
		return stamped
	}
	// A plain build inside the repository has VCS info; prefer the commit
	// line over the derived pseudo-version (vTAG.0.<time>-<hash>), which
	// is noisy. `go install …@vX` builds carry the module version but no
	// VCS info — that exact tag is what those users expect to see.
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		suffix := ""
		if commitDate != "" {
			suffix = " (" + commitDate + ")"
		}
		if dirty {
			suffix += " (modified)"
		}
		return "development build from commit " + rev + suffix
	}
	if mainVersion != "" && mainVersion != "(devel)" {
		return mainVersion
	}
	return "development build"
}

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
	case "rekey":
		err = rekeyCmd(os.Args[2:])
	case "version":
		fmt.Printf("gitcoffer %s\n", versionString())
	case "key":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "add":
			err = keyAddCmd(os.Args[3:])
		case "remove":
			err = keyRemoveCmd(os.Args[3:])
		case "list":
			err = keyListCmd(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "gitcoffer: unknown key subcommand %q\n\n", os.Args[2])
			usage()
			os.Exit(2)
		}
	case "gc":
		err = gcCmd(os.Args[2:])
	case "fsck":
		err = fsckCmd(os.Args[2:])
	case "doctor":
		err = doctorCmd(os.Args[2:])
	case "export-bundle":
		err = exportBundleCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "gitcoffer: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitcoffer: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  gitcoffer init <vault-directory>            create a new encrypted vault
  gitcoffer status <vault-directory>          inspect a vault (refs need the passphrase)
  gitcoffer rekey <vault-directory>           change the passphrase of the slot it opens
  gitcoffer key add <vault-directory>         add a passphrase slot (optionally -keyfile)
                                            [-keyfile <path>]
  gitcoffer key remove <vault-directory> <id> remove a key slot (never the last one)
  gitcoffer key list <vault-directory>        list key slots (no passphrase needed)
  gitcoffer gc [--dry-run] <vault-directory>  remove orphaned objects, temp files, old generations
  gitcoffer fsck <vault-directory>            verify every structure of the vault
  gitcoffer doctor <vault-directory>          check the environment and the vault, and report
  gitcoffer export-bundle <vault-dir> <file>  export the vault as a plain git bundle
  gitcoffer version                           print the build version
`)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer init <vault-directory>")
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

	first, err := promptPassword("Enter passphrase for the new vault")
	if err != nil {
		return err
	}
	second, err := promptPassword("Repeat passphrase")
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
		fmt.Fprintln(os.Stderr, "usage: gitcoffer status <vault-directory>")
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

	pass, err := promptPassword("Passphrase")
	if err != nil {
		return err
	}
	s, err := vault.Open(dir, pass)
	if err != nil {
		return err
	}
	m := s.Manifest()
	names := make([]string, 0, len(m.Refs))
	for name := range m.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	if f := s.FallbackFromGeneration(); f > 0 {
		fmt.Printf("  [warn] newest manifest generation %d is unreadable - showing generation %d; run gitcoffer fsck\n",
			f, s.ManifestNum())
	}
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

// stdinLines buffers non-terminal stdin across prompts: a fresh reader
// per prompt would swallow lines it buffered ahead.
var stdinLines *bufio.Reader

// promptPassword reads one passphrase after printing label. On a terminal
// it is hidden; when stdin is not a terminal (scripts, tests) one line is
// read instead — the same channel typing would use, so nothing is weaker.
func promptPassword(label string) (string, error) {
	fmt.Fprintln(os.Stderr, label+":")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if stdinLines == nil {
		stdinLines = bufio.NewReader(os.Stdin)
	}
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptNewPassword asks for a new passphrase twice and requires a
// non-empty match.
func promptNewPassword() (string, error) {
	first, err := promptPassword("New passphrase")
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", errors.New("passphrase must not be empty")
	}
	second, err := promptPassword("Repeat new passphrase")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passphrases do not match")
	}
	return first, nil
}

// openWithPrompt opens a vault after prompting for its passphrase.
func openWithPrompt(dir string) (*vault.Store, error) {
	pass, err := promptPassword("Passphrase")
	if err != nil {
		return nil, err
	}
	return vault.Open(dir, pass)
}

func vaultDirArg(fs *flag.FlagSet) string {
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	return fs.Arg(0)
}

func rekeyCmd(args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer rekey <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := vaultDirArg(fs)

	s, err := openWithPrompt(dir)
	if err != nil {
		return err
	}
	newPass, err := promptNewPassword()
	if err != nil {
		return err
	}
	if err := s.Rekey(newPass); err != nil {
		return err
	}
	fmt.Printf("Passphrase replaced for slot %d — vault.meta rewritten, object data untouched\n", s.OpenedSlotID())
	fmt.Println("If a credential helper cached the old passphrase, clear it before the next push (see the user guide's rekey note)")
	return nil
}

func keyAddCmd(args []string) error {
	fs := flag.NewFlagSet("key add", flag.ContinueOnError)
	keyfile := fs.String("keyfile", "", "require this key file in addition to the passphrase (created with random bytes if missing)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer key add [-keyfile <path>] <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := vaultDirArg(fs)

	s, err := openWithPrompt(dir)
	if err != nil {
		return err
	}
	newPass, err := promptNewPassword()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(*keyfile)
	created := *keyfile != "" && statErr != nil
	id, err := s.AddSlot(newPass, *keyfile)
	if err != nil {
		return err
	}
	if *keyfile == "" {
		fmt.Printf("Slot %d added (input: passphrase)\n", id)
		return nil
	}
	abs, _ := filepath.Abs(*keyfile)
	if created {
		fmt.Printf("Slot %d added (input: passphrase + key file)\n  key file created: %s\n", id, abs)
	} else {
		fmt.Printf("Slot %d added (input: passphrase + key file)\n  key file: %s\n", id, abs)
	}
	fmt.Println("  back the key file up separately from the vault — losing it locks this slot out")
	return nil
}

func keyRemoveCmd(args []string) error {
	fs := flag.NewFlagSet("key remove", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer key remove <vault-directory> <slot-id>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	dir := fs.Arg(0)
	id, err := strconv.Atoi(fs.Arg(1))
	if err != nil {
		return fmt.Errorf("slot id must be an integer: %v", err)
	}

	s, err := openWithPrompt(dir)
	if err != nil {
		return err
	}
	if err := s.RemoveSlot(id); err != nil {
		return err
	}
	fmt.Printf("Slot %d removed\n", id)
	return nil
}

func keyListCmd(args []string) error {
	fs := flag.NewFlagSet("key list", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer key list <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := vaultDirArg(fs)

	meta, err := vault.ReadMeta(dir)
	if err != nil {
		return err
	}
	fmt.Printf("vault %s — %d key slot(s):\n", meta.ID, len(meta.Slots))
	for _, sl := range meta.Slots {
		input := "passphrase"
		keyfile := ""
		if sl.Input == "passphrase+keyfile" {
			input = "passphrase + key file"
			keyfile = "  key file: " + sl.Keyfile
		}
		fmt.Printf("  slot %d: input %s, kdf %s (m=%d t=%d p=%d)%s\n",
			sl.ID, input, sl.KDF.Algo, sl.KDF.M, sl.KDF.T, sl.KDF.P, keyfile)
	}
	return nil
}

func gcCmd(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "report what would be removed without deleting anything")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer gc [--dry-run] <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := vaultDirArg(fs)

	pass, err := promptPassword("Passphrase")
	if err != nil {
		return err
	}
	if *dryRun {
		rep, err := vault.GCDryRun(dir, pass)
		if err != nil {
			return err
		}
		for _, name := range rep.RemovedObjects {
			fmt.Printf("would remove orphaned object %s\n", name)
		}
		for _, name := range rep.RemovedTmp {
			fmt.Printf("would remove temp file %s\n", name)
		}
		for _, n := range rep.PrunedGenerations {
			fmt.Printf("would prune manifest generation %d\n", n)
		}
		fmt.Printf("gc dry-run: would remove %d object(s), %d temp file(s), %d generation(s), freeing %s\n",
			len(rep.RemovedObjects), len(rep.RemovedTmp), len(rep.PrunedGenerations), humanBytes(rep.BytesFreed))
		return nil
	}
	rep, err := vault.GC(dir, pass)
	if err != nil {
		return err
	}
	for _, name := range rep.RemovedObjects {
		fmt.Printf("removed orphaned object %s\n", name)
	}
	for _, name := range rep.RemovedTmp {
		fmt.Printf("removed temp file %s\n", name)
	}
	for _, n := range rep.PrunedGenerations {
		fmt.Printf("pruned manifest generation %d\n", n)
	}
	fmt.Printf("gc complete: %d object(s), %d temp file(s), %d generation(s) removed, %s freed\n",
		len(rep.RemovedObjects), len(rep.RemovedTmp), len(rep.PrunedGenerations), humanBytes(rep.BytesFreed))
	return nil
}

func fsckCmd(args []string) error {
	fs := flag.NewFlagSet("fsck", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer fsck <vault-directory>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := vaultDirArg(fs)

	pass, err := promptPassword("Passphrase")
	if err != nil {
		return err
	}
	findings, err := vault.Fsck(dir, pass)
	if err != nil {
		return err
	}
	errs := 0
	for _, f := range findings {
		fmt.Println(f)
		if f.Err {
			errs++
		}
	}
	if errs > 0 {
		return fmt.Errorf("fsck found %d error(s)", errs)
	}
	fmt.Println("fsck complete: no errors found")
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
