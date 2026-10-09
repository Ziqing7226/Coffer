// Package packproc wraps the git plumbing Coffer uses to move and inventory
// packs, so pack handling is never reimplemented (docs/architecture.md,
// "pack glue"). Commands that must run in the caller's repository keep the
// inherited environment; commands on scratch repositories get a cleaned
// environment so they never touch the caller's repo.
package packproc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CleanGitEnv strips the caller's repo context (GIT_DIR and friends) so
// subprocesses operate on scratch repositories, not the repository invoking
// the helper.
func CleanGitEnv() []string {
	drop := []string{
		"GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=",
		"GIT_OBJECT_DIRECTORY=", "GIT_ALTERNATE_OBJECT_DIRECTORIES=",
		"GIT_CONFIG=", "GIT_CONFIG_PARAMETERS=", "GIT_CONFIG_COUNT=",
		"GIT_COMMON_DIR=", "GIT_PREFIX=",
	}
	var env []string
	for _, e := range os.Environ() {
		keep := true
		for _, p := range drop {
			if strings.HasPrefix(e, p) {
				keep = false
				break
			}
		}
		if keep {
			env = append(env, e)
		}
	}
	return env
}

// TempBareRepo creates a scratch bare repository; the returned cleanup
// removes it.
func TempBareRepo() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "coffer-repo-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	cmd := exec.Command("git", "init", "--bare", "--quiet", "-b", "main", dir)
	cmd.Env = CleanGitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git init: %v: %s", err, out)
	}
	return dir, cleanup, nil
}

// BuildPack runs `git pack-objects --stdout --revs` in the CALLER's
// repository (inherited environment and working directory) and stores the
// pack in a temp file. Push uses this: git never sends the helper a pack.
func BuildPack(revs []string) (packPath string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "coffer-pack-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(tmp) }
	packPath = filepath.Join(tmp, "push.pack")
	f, err := os.Create(packPath)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	cmd := exec.Command("git", "pack-objects", "--stdout", "--revs")
	cmd.Stdin = strings.NewReader(strings.Join(revs, "\n") + "\n")
	cmd.Stdout = f
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	f.Close()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("pack-objects: %v: %s", err, stderr.String())
	}
	return packPath, cleanup, nil
}

// ObjectCount parses the pack header and returns the object count, erroring
// when the file is not a packfile.
func ObjectCount(packPath string) (uint32, error) {
	f, err := os.Open(packPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return 0, fmt.Errorf("reading pack header: %w", err)
	}
	if string(hdr[:4]) != "PACK" {
		return 0, fmt.Errorf("%s is not a packfile", packPath)
	}
	return binary.BigEndian.Uint32(hdr[8:12]), nil
}

// IndexPack verifies packPath by indexing it inside a scratch repository
// and returns the object ids the pack contains.
func IndexPack(packPath string) (oids []string, cleanup func(), err error) {
	repo, cleanup, err := TempBareRepo()
	if err != nil {
		return nil, nil, err
	}
	idx := packPath + ".idx"
	cmd := exec.Command("git", "index-pack", "-o", idx, packPath)
	cmd.Dir = repo
	cmd.Env = CleanGitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("index-pack: %v: %s", err, out)
	}
	oids, err = ShowIndex(idx)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return oids, cleanup, nil
}

// ShowIndex lists the object ids recorded in an idx file. Output lines are
// "<offset> <oid> (<crc>)", so the oid is the second field.
func ShowIndex(idxPath string) ([]string, error) {
	f, err := os.Open(idxPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cmd := exec.Command("git", "show-index")
	cmd.Stdin = f
	cmd.Env = CleanGitEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("show-index: %v", err)
	}
	var oids []string
	for _, line := range strings.Split(out.String(), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && len(fields[1]) >= 40 {
			oids = append(oids, fields[1])
		}
	}
	return oids, nil
}

// PipePackToCaller rebuilds a pack for revs from the packs stored in
// repoDir (a scratch repository) and streams it straight into
// `git index-pack --stdin --fix-thin` in the CALLER's repository. Fetch uses
// this: objects are imported into the caller's object database and no pack
// ever crosses the helper protocol.
func PipePackToCaller(repoDir string, revs []string) error {
	src := exec.Command("git", "pack-objects", "--stdout", "--revs")
	src.Dir = repoDir
	src.Env = CleanGitEnv()
	src.Stdin = strings.NewReader(strings.Join(revs, "\n") + "\n")

	dst := exec.Command("git", "index-pack", "--stdin", "--fix-thin")
	// Separate buffers: the two processes' stderr is copied concurrently by
	// separate goroutines, and bytes.Buffer is not safe for that.
	var srcErrBuf, dstErrBuf bytes.Buffer
	src.Stderr, dst.Stderr = &srcErrBuf, &dstErrBuf

	pipe, err := dst.StdinPipe()
	if err != nil {
		return err
	}
	src.Stdout = pipe
	if err := dst.Start(); err != nil {
		return fmt.Errorf("index-pack: %v", err)
	}
	srcErr := src.Run()
	pipe.Close()
	dstErr := dst.Wait()
	if srcErr != nil || dstErr != nil {
		return fmt.Errorf("serve fetch (pack-objects: %v: %s, index-pack: %v: %s)",
			srcErr, srcErrBuf.String(), dstErr, dstErrBuf.String())
	}
	return nil
}

// IndexPackInDir regenerates the idx for packPath inside repoDir (used on
// the fetch path to revive stored packs in a scratch repository).
func IndexPackInDir(repoDir, packPath string) error {
	cmd := exec.Command("git", "index-pack", packPath)
	cmd.Dir = repoDir
	cmd.Env = CleanGitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("index-pack: %v: %s", err, out)
	}
	return nil
}

// ResolveInCaller resolves a revision in the repository invoking the helper.
func ResolveInCaller(rev string) (string, error) {
	out, err := exec.Command("git", "rev-parse", "--verify", rev).Output()
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

// ExistsInCaller reports whether an object exists in the caller's repo.
func ExistsInCaller(oid string) bool {
	return exec.Command("git", "cat-file", "-e", oid+"^{object}").Run() == nil
}

// CallerObjectFormat returns the object format of the repository invoking
// the helper ("sha1" or "sha256").
func CallerObjectFormat() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-object-format").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-object-format: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// CallerIsShallow reports whether the repository invoking the helper is a
// depth-limited (shallow) clone, whose history is truncated.
func CallerIsShallow() (bool, error) {
	out, err := exec.Command("git", "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		return false, fmt.Errorf("git rev-parse --is-shallow-repository: %v", err)
	}
	switch strings.TrimSpace(string(out)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("unexpected --is-shallow-repository output %q", string(out))
}
