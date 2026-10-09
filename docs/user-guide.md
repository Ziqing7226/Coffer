# User Guide

Coffer turns a directory on an external or secondary disk into an encrypted
git remote. `git push` works exactly as always; the bytes that reach the
disk are ciphertext. This guide covers installation, everyday use, key
management, recovery on a new machine, and maintenance.

## Requirements

- git ≥ 2.30 on `PATH`
- The two Coffer binaries, `git-remote-coffer` and `coffer`, on `PATH`
  (git discovers the helper through `PATH`)
- A vault on a *different physical disk* than your working copy — that is
  the point: one disk failure must not destroy both

## Install

**Download a release** (Linux, Windows, macOS; amd64 and arm64) from the
[releases page](https://github.com/Ziqing7226/Coffer/releases), unpack, and
put both binaries on `PATH`. Verify with:

```console
$ coffer version
coffer 1.0.0-pre
$ git-remote-coffer          # run with no arguments, prints its usage note;
                             # normally git invokes it for you
```

**Build from source** with Go ≥ 1.27:

```console
$ go install github.com/Ziqing7226/Coffer/cmd/coffer@v1.0.0-pre
$ go install github.com/Ziqing7226/Coffer/cmd/git-remote-coffer@v1.0.0-pre
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
$ coffer init /mnt/usb/myproject.coffer
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
| `coffer init <dir>` | create a new vault (prompts for a new passphrase) |
| `coffer status <dir>` | inspect a vault: format, slots, refs, packs |
| `coffer rekey <dir>` | change the passphrase of the slot it opens |
| `coffer key add <dir> [-keyfile <path>]` | add a passphrase slot, optionally requiring a key file as a second factor |
| `coffer key remove <dir> <id>` | remove a key slot (never the last one) |
| `coffer key list <dir>` | list key slots (no passphrase needed) |
| `coffer gc <dir>` | remove orphaned objects, temp files, old manifest generations |
| `coffer fsck <dir>` | verify every structure of the vault |
| `coffer version` | print the build version |

Passphrase prompts read from the terminal (hidden); when stdin is not a
terminal — scripts, CI — each prompt reads one line, so every subcommand
is scriptable.

## Keys and recovery

**There is no passphrase recovery, by design.** The passphrase (plus a
key file, if that slot requires one) is the only way in. A key file adds
a second factor; losing it locks out every slot that requires it.

- Rotate your passphrase on a schedule: `coffer rekey` rewrites only the
  tiny `vault.meta` — object data is never re-encrypted, so it is fast at
  any vault size.
- A rekey makes cached credentials stale. If pushes suddenly fail with
  *authentication failed* after a rekey, clear the cached value:
  `printf 'protocol=coffer\nhost=coffer\npath=<vault id>\n\n' | git credential reject`
- Share access with a collaborator or machine by adding a slot
  (`coffer key add`) instead of sharing one passphrase.

**Recovering on a fresh machine:** install git and Coffer, mount the
medium, `git clone coffer::<path>`, enter the passphrase. Keeping a copy
of the release archive next to the vault is a convenience for offline
bootstrapping, never a dependency.

## Maintenance

- `coffer fsck` verifies every AEAD seal, the manifest chain, and every
  object's checksum; run it when a medium had a rough day. It reports the
  first divergence per structure and never attempts recovery.
- `coffer gc` reclaims space from interrupted pushes (orphaned object
  files), leftover temp files, and old manifest generations. It refuses to
  delete anything if any manifest generation fails to decrypt.
- Both commands serialize with writers through the vault lock; concurrent
  pushes queue safely rather than corrupting.

## Troubleshooting

| Symptom | Meaning and fix |
|---|---|
| `not a coffer vault` on push | The remote URL does not point at a vault. Check the path, or run `coffer init`. |
| `authentication failed` on every operation | Wrong passphrase, or a credential helper answers with a stale value (common right after a rekey). Evict it with the `git credential reject` line above. |
| `key file ... no such file` | A second-factor slot's key file is missing at its recorded path. Restore it; nothing else will unlock that slot. |
| `key file ... is not a regular file` | The recorded path is a symlink, device, or oversized (>1 MiB) file. Coffer refuses such paths because they come from on-media metadata — point the slot at the real file instead. |
| Push refused: repository is shallow | The push came from a depth-limited clone, whose history is truncated. Run `git fetch --unshallow` against its current origin and push again. |
| Push or fetch refused: repository uses sha256 object ids | The vault format speaks sha1 object ids. Re-create the repository with the default sha1 format (`git init` without `--object-format=sha256`). |
| `another coffer operation is writing` | A concurrent writer holds the vault lock. Wait, or — if you are certain none is running — delete `<vault>/vault.lock`. |
| Clone of a non-`main` repository checks out an empty tree | Fixed in 1.0.0-pre: the alphabetically first branch is advertised as HEAD. Update both binaries. |

## Security notes

The threat model, in full, is [threat-model.md](threat-model.md). In
short: the medium at rest reveals only file count, approximate sizes, and
timestamps — never content, file names, or ref names. Coffer does not
protect a host that is compromised *while* the vault is open, and it
provides no deniability. The format is frozen and pinned by published
[test vectors](test-vectors.json).
