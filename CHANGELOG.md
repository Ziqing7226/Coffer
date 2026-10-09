# Changelog

## Unreleased (toward 1.0.0)

- `gitgitcoffer export-bundle <vault> <file>` — the guaranteed exit path: a
  plain, stock-git-readable bundle of everything in the vault.
- `gitgitcoffer doctor <vault>` — environment and vault health check (git
  version, helper discoverability, meta shape, key-file presence,
  filesystem characteristics, leftover state).
- `gitgitcoffer gc --dry-run` — report what would be reclaimed without
  deleting.
- Pushes from Git-LFS-configured repositories warn that LFS content is
  not part of the vault.
- Independent security review (three cold reviewers) — all confirmed
  findings fixed: unbounded reads of untrusted metadata, crafted
  `vault.meta` shapes, future-dated planted locks, sha256 and shallow
  caller guards, `--atomic` report contract, commit-race narrowing,
  locked meta rewrites, append-tamper detection, vector parameter
  pinning.
- Disk-full robustness suite (user-namespace tmpfs, free-space sweep).
- Security policy ([SECURITY.md](SECURITY.md)); support matrix
  ([docs/support-matrix.md](docs/support-matrix.md)).

## 1.0.0-pre

First pre-release: vault format v1 (frozen, pinned by
[docs/test-vectors.json](docs/test-vectors.json)), remote helper with
progress milestones, writer lock, `--atomic`/`--force-with-lease`,
credential approval, HEAD fallback for non-main repositories; full
`gitcoffer` CLI (init, status, key add/remove/list, rekey, gc, fsck,
version); security-reviewed; six-platform release binaries.
