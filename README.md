<div align="center">
  <img src="docs/assets/coffer.svg" width="140" alt="Coffer logo" />
</div>

<h1 align="center">GitCoffer</h1>

<p align="center">
  <strong>An encrypted git remote on your own disk.</strong><br>
  Push from any git client — including VSCode — straight into a
  password-protected vault on a second disk or USB drive.
</p>

<p align="center">
  <img alt="version 1.0.0-pre" src="https://img.shields.io/badge/version-1.0.0--pre-blue">
  &nbsp;
  <img alt="platforms" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-6e7681">
  &nbsp;
  <img alt="license" src="https://img.shields.io/badge/license-MIT-6e7681">
</p>

<p align="center">
  <img src="docs/assets/workflow.png" alt="git push, encrypted by Argon2id and XChaCha20-Poly1305, stored in a vault on a USB drive" width="720">
</p>

---

Coffer turns any directory on a removable or secondary disk into a fully
encrypted git remote. `git push` works exactly the way it always has — but
the bytes that reach the disk are ciphertext. Whoever finds the drive finds
random-looking files; with the passphrase, the complete repository — every
branch, tag, and commit — is reconstructed from the vault alone.

Vault format v1 is frozen and pinned by published
[test vectors](docs/test-vectors.json). This is the **1.0.0-pre** release:
fully functional and tested — including crash, corruption, and
real-external-media batteries — with packaging-store submissions and final
polish to come in 1.0.0.

## Why

<p align="center">
  <img src="docs/assets/why-coffer.png" alt="A vault at the center, surrounded by: no third party, single static binary, cross-platform, native git clients" width="560">
</p>

- **No third party.** The remote is a directory you control — a USB stick,
  an external drive, a second internal disk. Nothing ever leaves your
  hardware; the code contains no networking at all.
- **Encrypted at rest.** The entire repository — objects, refs, history — is
  sealed under passphrase encryption (Argon2id key derivation,
  XChaCha20-Poly1305 AEAD). Possessing the drive is not enough.
- **Stock git, unchanged.** Coffer is a standard
  [git remote helper](docs/architecture.md). No forked git, no wrappers to
  remember, no server to run. If `git push` works, Coffer works — and so does
  the VSCode Sync button.
- **Single static binary.** No GPG, no FUSE, no drivers, no administrator
  rights. The vault is plain files, so exFAT and FAT32 media are fully
  supported.

## How it works

Git delegates transport for unknown URL schemes to a helper binary: a
`coffer::<path>` remote makes git invoke `git-remote-coffer`. On push, the
helper reads the objects straight from your repository, encrypts them, and
writes them into the vault; on fetch it does the reverse, importing
decrypted objects back into your object database. Git never notices the
difference — which is why every git client stays compatible. Requirements:
stock git ≥ 2.30 (where the helper `object-format` capability first
appeared) and the two GitCoffer binaries on `PATH`. The design and its
rationale are in [docs/architecture.md](docs/architecture.md); the on-disk
layout is normative in [docs/format-spec.md](docs/format-spec.md).

## Install

Download a release for your platform — Linux, Windows, macOS, amd64 or
arm64 — from the [releases page](https://github.com/Ziqing7226/GitCoffer/releases),
unpack, and put both `gitcoffer` and `git-remote-coffer` on `PATH` (git finds
the helper through `PATH`; no administrator rights needed). Verify:

```console
$ gitcoffer version
gitcoffer v1.0.0-rc.1
```

The version line is self-describing: release archives print the
release version, `go install …@vX` prints that exact version, and a
build from the repository reports the commit it was built from.

Or build from source with Go ≥ 1.27:

```console
$ go install github.com/Ziqing7226/GitCoffer/cmd/gitcoffer@v1.0.0-pre
$ go install github.com/Ziqing7226/GitCoffer/cmd/git-remote-coffer@v1.0.0-pre
```

Package-manager entries (Homebrew, scoop, winget) arrive with the stable
1.0.0 release.

## Quick start

```console
$ gitcoffer init /mnt/usb/myproject.coffer
Enter passphrase for the new vault: ********
Repeat passphrase: ********
Vault created: /mnt/usb/myproject.coffer

$ git remote add origin coffer::/mnt/usb/myproject.coffer
$ git push -u origin main
Enumerating objects: 42, done.
Writing objects: 100% (42/42), done.
To coffer::/mnt/usb/myproject.coffer
 * [new branch]      main -> main
```

From then on, `git pull`, `git fetch`, `git clone`, and VSCode's Sync
button all work against the vault. The passphrase is requested through
git's own credential flow — terminal prompt, native VSCode input box, or a
configured credential helper (`--atomic` and `--force-with-lease` work as
with any remote). On Windows:
`git remote add origin coffer::D:\backups\myproject.coffer`; on macOS:
`coffer::/Volumes/Backup/myproject.coffer`. To clone on another machine,
only git, Coffer, and the passphrase are needed:
`git clone coffer::/mnt/usb/myproject.coffer`.

### Nicer remote URLs

```console
$ git config --global url."coffer::/mnt/usb/".insteadOf "usb://"
$ git remote add origin usb://myproject.coffer
```

### The coffer CLI

| Command | Purpose |
|---|---|
| `gitcoffer init <dir>` | create a new vault |
| `gitcoffer status <dir>` | inspect: format, slots, refs, packs |
| `gitcoffer rekey <dir>` | change the passphrase (data is never re-encrypted) |
| `gitcoffer key add / remove / list` | manage key slots; optional key-file second factor |
| `gitcoffer gc [--prune] <dir>` | report reclaimable space, or reclaim it with `--prune` |
| `gitcoffer fsck <dir>` | verify every structure of the vault |
| `gitcoffer doctor <dir>` | check the environment and the vault |
| `gitcoffer export-bundle <dir> <file>` | export the vault as a plain git bundle — the exit path |
| `gitcoffer version` | print the build version |

Full walkthrough — keys and recovery, maintenance, troubleshooting:
[docs/user-guide.md](docs/user-guide.md).

## Security scope

<p align="center">
  <img src="docs/assets/locked-vs-open.png" alt="Left: someone finding the drive sees only scrambled scribbles. Right: with the passphrase, the vault opens into an orderly commit history." width="640">
</p>

Coffer protects **repository data at rest on the remote medium**.

| In scope | Out of scope |
|---|---|
| Lost, stolen, copied, or forensically imaged drives | A host compromised *while* the vault is in use |
| Failure of the original working disk — the vault is a complete backup | A forgotten passphrase — there is no recovery, by design |
| Bit-rot and tampering with vault files (AEAD-verified) | Hiding vault metadata such as file count and approximate sizes |

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Choosing an approach

Encrypting git backups has three mature shapes, each fitting different
needs — the right choice is whatever matches yours:

- **Encrypting individual files inside the repository** — the natural fit
  when the remote host must stay readable, for example while collaborating
  through a public git host.
- **An encrypted volume holding a bare repository** — natural when you
  already work with encrypted volumes and don't mind mounting one before
  every push.
- **An encrypted remote helper** — the whole remote is ciphertext; `git
  push` stays a single step, on every platform, with no drivers or daemons.

Coffer lives in the third shape. Its design follows the path that
[git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt) proved
on Linux, and aims to offer it everywhere with no dependencies — we are
grateful for the ground it broke.

## Documentation

| Document | Purpose |
|---|---|
| [User guide](docs/user-guide.md) | install, everyday use, keys and recovery, maintenance |
| [Architecture](docs/architecture.md) | design decisions, components, protocol flows |
| [Vault format specification](docs/format-spec.md) | normative on-disk format — build against this |
| [Support matrix](docs/support-matrix.md) | tested configurations and explicit boundaries |
| [Threat model](docs/threat-model.md) | what Coffer does and does not protect |
| [Development plan](docs/development.md) | stack, phases, testing strategy, conventions |
| [Contributing](CONTRIBUTING.md) | repository rules and how to contribute |

## Contributing

Issues and pull requests are welcome — holes in the threat model, gaps in
the guide, portability reports, and fixes all count. All artifacts in this
repository are written in English; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
