# Support matrix

What Coffer is tested on, and where its boundaries are. The honest
version — if something below says "refused" or "not backed up", the tool
enforces or documents it rather than failing silently.

## Tested configurations

Every release tag's CI runs the full suite (unit, golden e2e against real
git, crash injection, corruption matrix) on:

| Axis | Coverage |
|---|---|
| OS | Linux (ubuntu-latest), Windows (windows-latest), macOS (macos-latest) |
| Filesystems | ext4, NTFS, APFS (runner-native); FAT32 on real external USB media (local battery) |
| git | Current stable per runner image, plus a dedicated CI leg running the full suite against git 2.30.0 built from source — the supported floor is exercised on every push, not asserted |
| Architectures | amd64 and arm64, built and cross-compiled on every push |

Reference performance on FAT32 USB media (10k commits): full push 6.1 s,
fresh clone 3.4 s, incremental push 3.5 s — see
[development.md](development.md) for the measured run.

## Explicit boundaries

| Situation | Behavior |
|---|---|
| sha256 repositories | Push and fetch are **refused** with a clear error: the vault format speaks sha1 object ids, and a mixed vault could never be served back. |
| Shallow (depth-limited) clones | Push is **refused** with the `git fetch --unshallow` remedy: a shallow push would store truncated history and poison later incremental pushes. CI checkouts are shallow — unshallow them before backing up. |
| Git LFS | **Not backed up.** LFS content lives on LFS servers, outside the git object store; the vault holds only pointer files. Pushes from LFS-configured repositories print a warning. Keep LFS objects backed up separately. |
| Submodules | The gitlink (commit pointer) is stored like any ref content; the submodule's own repository is a separate repository and is **not** included. Back each submodule up on its own. |
| FAT32 / exFAT media | Fully supported (plain files, no permissions needed), with one boundary: these filesystems cap a single file at ~4 GiB, and one vault object file holds one pack — repositories whose packs exceed that need a filesystem without the cap. `gitcoffer doctor` warns when it detects such media. |
| Case-insensitive filesystems | Safe: vault file names are lowercase hex digits only. |
| Non-ASCII and spaced paths | Fully supported in repository content and vault paths. |
| Bare repositories | Pushing from a bare repository works — the object flow is identical. |
| `--atomic`, `--force-with-lease`, `--dry-run`, deletions, annotated tags | Supported and covered by the e2e suite. |
| Non-fast-forward pushes | Enforced server-side: a branch that exists in the vault only moves to a descendant of its current tip unless forced — an unrelated repository cannot silently overwrite it. |
| Refs other than branches and tags | Any fully-qualified ref (e.g. `refs/notes/*`) round-trips. |

## Recovery scope

The vault plus the passphrase reconstruct every ref and the complete
history of each, on any supported machine, with `git clone`. Two things a
vault deliberately does not carry: the original repository's HEAD choice
(clones check out `main`, then `master`, then the alphabetically first
branch) and reflogs. `gitcoffer export-bundle` writes a plain git bundle of
everything, readable by stock git alone.
