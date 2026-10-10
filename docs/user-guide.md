# User Guide

Coffer turns a directory on an external or secondary disk into an encrypted
git remote. `git push` works exactly as always; the bytes that reach the
disk are ciphertext. This guide covers installation, everyday use, key
management, recovery on a new machine, and maintenance.

## Requirements

- git ≥ 2.30 on `PATH`
- The two GitCoffer binaries, `git-remote-coffer` and `gitcoffer`, on `PATH`
  (git discovers the helper through `PATH`)
- A vault on a *different physical disk* than your working copy — that is
  the point: one disk failure must not destroy both

## Install

**Download a release** (Linux, Windows, macOS; amd64 and arm64) from the
[releases page](https://github.com/Ziqing7226/GitCoffer/releases), unpack, and
put both binaries on `PATH`. Verify with:

```console
$ gitcoffer version
gitcoffer v1.0.0-rc.1
$ git-remote-coffer          # run with no arguments, prints its usage note;
                             # normally git invokes it for you
```

On Windows, the PowerShell installer
(`scripts/install.ps1`) does the same through `Invoke-WebRequest`. For
tab completion, load the script for your shell from your profile:
`gitcoffer completion bash` (also `zsh`, `fish`, `powershell`).

The version line is self-describing: release archives print the
release version, `go install …@vX` prints that exact version, and a
repository build reports the commit it was built from.

**Build from source** with Go ≥ 1.27:

```console
$ go install github.com/Ziqing7226/GitCoffer/cmd/gitcoffer@v1.0.0-pre
$ go install github.com/Ziqing7226/GitCoffer/cmd/git-remote-coffer@v1.0.0-pre
```

Package-manager entries (Homebrew, scoop, winget) ship with the stable
1.0.0 release.

**Windows note:** add the install directory to `PATH` via system settings;
no administrator rights are needed anywhere.

## Quick start

Pick the vault path for your platform — Linux `/mnt/usb/…`,
macOS `/Volumes/<volume>/…`, Windows `D:\backups\…` — and substitute it
in the commands below (shown with the Linux path):

```console
$ gitcoffer init /mnt/usb/myproject.coffer
Enter passphrase for the new vault: ********
Repeat passphrase: ********
Vault created: /mnt/usb/myproject.coffer

$ cd myproject
$ git remote add origin coffer::/mnt/usb/myproject.coffer
$ git push -u origin main
```

From then on, `git pull`, `git fetch`, `git clone`, and VSCode's Sync
button all work against the vault. The passphrase is requested through
git's own credential flow once per operation — as a terminal prompt, as a
native VSCode input box, or silently from a credential helper you have
configured.

On another machine that knows the passphrase:

```console
$ git clone coffer::/mnt/usb/myproject.coffer
```

Everything — every branch, tag, and commit — is reconstructed from the
vault alone. A git repository is ~40 MB of history? The vault is a
complete backup, not a mirror of your working files.

### Multiple projects: one vault each

A vault is one git repository, exactly like one URL on a public host is
one repository. Two projects pushing `main` into the same vault share
that ref — the second push moves or (with `--force`) overwrites the
first, because that is what pushing two `main`s to one repository
means; git refuses non-fast-forward updates without `--force`, so the
protection is the same as on any remote. Keep one project per vault;
if you deliberately share a vault, give each project its own branch
name (`repo1-main`, `repo2-main`) — everything else (fsck, gc, keys)
treats the vault as a whole.

### Passphrases on Windows

Interactive use needs nothing special: git prompts in the terminal, and
VSCode shows its native input box. For scripted use, prefer git's
credential system over GIT_ASKPASS — askpass scripts are awkward in
cmd/batch (a `.bat` `echo` ends lines with CRLF, and any layer that
passes the carriage return into the passphrase breaks authentication;
GitCoffer trims it defensively, but not every tool in the chain does):

```console
$ git config credential.helper store        # or: manager (Credential Manager)
$ printf "protocol=coffer\nhost=coffer\npath=<vault id>\nusername=coffer\npassword=<passphrase>\n\n" | git credential approve
```

(In PowerShell, pipe a double-quoted string with `` `n `` line breaks
instead of printf.)

After a successful push the passphrase is approved to git, so a helper
like Windows Credential Manager may cache it. That is the feature
working — but after `gitcoffer rekey` you must evict the cached value
before the next push, or the old passphrase keeps answering (the
authentication-failure error names this fix):

```console
$ printf "protocol=coffer\nhost=coffer\npath=<vault id>\nusername=coffer\n\n" | git credential reject
```

### Nicer remote URLs

```console
$ git config --global url."coffer::/mnt/usb/".insteadOf "usb://"
$ git remote add origin usb://myproject.coffer
```

## How it works (one paragraph)

Coffer is a standard
[git remote helper](https://git-scm.com/docs/gitremote-helpers): when git
sees a `coffer::<path>` URL it runs `git-remote-coffer`, which reads the
pushed objects straight from your repository, encrypts them
(Argon2id key derivation, XChaCha20-Poly1305 AEAD), and stores them in the
vault directory; on fetch it does the reverse. Git never notices the
difference, which is why every git client — including VSCode — works
unchanged. The on-disk format is specified and frozen in
[format-spec.md](format-spec.md).

## The coffer CLI

| Command | Purpose |
|---|---|
| `gitcoffer init <dir>` | create a new vault (prompts for a new passphrase) |
| `gitcoffer status <dir>` | inspect a vault: format, slots, refs, packs |
| `gitcoffer rekey <dir>` | change the passphrase of the slot it opens |
| `gitcoffer key add <dir> [-keyfile <path>]` | add a passphrase slot, optionally requiring a key file as a second factor |
| `gitcoffer key remove <dir> <id>` | remove a key slot (never the last one) |
| `gitcoffer key list <dir>` | list key slots (no passphrase needed) |
| `gitcoffer gc [--prune] <dir>` | report orphaned objects, temp files, old generations — `--prune` actually removes them |
| `gitcoffer fsck <dir>` | verify every structure of the vault |
| `gitcoffer doctor <dir>` | check the environment and the vault, and report |
| `gitcoffer export-bundle <dir> <file>` | export the vault as a plain git bundle |
| `gitcoffer version [--json]` | print the build version (optionally as JSON) |
| `gitcoffer completion <shell>` | print a completion script for bash, zsh, fish, or powershell |

Passphrase prompts read from the terminal (hidden); when stdin is not a
terminal — scripts, CI — each prompt reads one line, so every subcommand
is scriptable.

## Keys and recovery

**There is no passphrase recovery, by design.** The passphrase (plus a
key file, if that slot requires one) is the only way in. A key file adds
a second factor; losing it locks out every slot that requires it.

- Rotate your passphrase on a schedule: `gitcoffer rekey` rewrites only the
  tiny `vault.meta` — object data is never re-encrypted, so it is fast at
  any vault size.
- A rekey makes cached credentials stale. If pushes suddenly fail with
  *authentication failed* after a rekey, clear the cached value:
  `printf 'protocol=coffer\nhost=coffer\npath=<vault id>\n\n' | git credential reject`
- Share access with a collaborator or machine by adding a slot
  (`gitcoffer key add`) instead of sharing one passphrase.

**Recovering on a fresh machine:** install git and Coffer, mount the
medium, `git clone coffer::<path>`, enter the passphrase. Keeping a copy
of the release archive next to the vault is a convenience for offline
bootstrapping, never a dependency.

## Leaving, and being sure you can

`gitcoffer export-bundle <vault> <file.bundle>` decrypts the vault into a
standard git bundle that stock git alone can clone or verify — the exit
path needs neither Coffer nor the vault format. The bundle file itself
is plaintext, so store it accordingly. The bundle is a point-in-time
snapshot: a push that lands while the export runs is simply not in it
(export never blocks writers). `gitcoffer doctor <vault>` gives a
one-shot health report of the environment and the vault; boundaries of
what is supported (LFS content, submodules, sha256, shallow clones,
FAT32 file-size caps) are listed in
[support-matrix.md](support-matrix.md).

## Maintenance

- `gitcoffer fsck` verifies every AEAD seal, the manifest chain, and every
  object's checksum; run it when a medium had a rough day. It reports the
  first divergence per structure and never attempts recovery.
- `gitcoffer gc` reports reclaimable space from interrupted pushes
  (orphaned object files), leftover temp files, and old manifest
  generations; `--prune` performs the deletion. It refuses to delete
  anything if any manifest generation fails to decrypt. One honest
  caveat: the vault is a remote, not an immutable archive — once you
  delete a ref and run `gitcoffer gc --prune`, objects only that ref
  referenced are gone from the vault (they live on wherever else you
  pushed them).
- Both commands serialize with writers through the vault lock; concurrent
  pushes queue safely rather than corrupting.

## Troubleshooting

| Symptom | Meaning and fix |
|---|---|
| `not a coffer vault` on push | The remote URL does not point at a vault. Check the path, or run `gitcoffer init`. |
| `authentication failed` on every operation | Wrong passphrase, or a credential helper answers with a stale value (common right after a rekey). Evict it with the `git credential reject` line above. |
| `key file ... no such file` | A second-factor slot's key file is missing at its recorded path. Restore it; nothing else will unlock that slot. |
| `key file ... is not a regular file` | The recorded path is a symlink, device, or oversized (>1 MiB) file. Coffer refuses such paths because they come from on-media metadata — point the slot at the real file instead. |
| Push refused: repository is shallow | The push came from a depth-limited clone, whose history is truncated. Run `git fetch --unshallow` against its current origin and push again. |
| Push or fetch refused: repository uses sha256 object ids | The vault format speaks sha1 object ids. Re-create the repository with the default sha1 format (`git init` without `--object-format=sha256`). |
| LFS repository: push fails with `batch request: missing protocol` | Expected: git-lfs does not support `coffer::` remotes. The vault stores only the LFS pointer files (the push prints a warning). Remove the lfs pre-push hook if you want the pointers in the vault, and back the LFS objects up separately. |
| Push refused: non-fast-forward | The vault's branch would be overwritten by unrelated or rewritten history. Fetch and merge first; `--force` overwrites deliberately — the overwritten commits become unrecoverable after `gitcoffer gc --prune`. |
| `another coffer operation is writing` | A concurrent writer holds the vault lock. On Windows, a crashed holder's lock is stolen as soon as its pid is detected dead; on any platform, if you are certain none is running you can delete `<vault>/vault.lock` directly. |
| Clone of a non-`main` repository checks out an empty tree | Fixed in 1.0.0-pre: the alphabetically first branch is advertised as HEAD. Update both binaries. |

## Security notes

The threat model, in full, is [threat-model.md](threat-model.md). In
short: the medium at rest reveals only file count, approximate sizes, and
timestamps — never content, file names, or ref names. Coffer does not
protect a host that is compromised *while* the vault is open, and it
provides no deniability. The format is frozen and pinned by published
[test vectors](test-vectors.json).
