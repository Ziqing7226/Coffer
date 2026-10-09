// Command git-remote-coffer is the GitCoffer remote helper: git invokes it for
// coffer::<path> URLs and speaks the remote-helper protocol over stdio.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Ziqing7226/GitCoffer/internal/proto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "git-remote-coffer: missing URL argument")
		os.Exit(128)
	}
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "git-remote-coffer: git executable not found on PATH — Coffer drives git's plumbing commands; install git and retry")
		os.Exit(128)
	}
	// The last argument is always the URL/address: either a configured
	// remote's URL ("coffer::<path>") or, when the URL was given directly
	// on the command line, the bare <path> itself.
	addr := os.Args[len(os.Args)-1]
	vaultDir := strings.TrimPrefix(addr, "coffer::")
	if vaultDir == "" {
		fmt.Fprintln(os.Stderr, "git-remote-coffer: empty vault path in URL")
		os.Exit(128)
	}

	if err := proto.Run(vaultDir, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-coffer: %v\n", err)
		os.Exit(128)
	}
}
