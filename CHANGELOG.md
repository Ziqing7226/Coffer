# Changelog

## 1.0.0 (2026-10-10)

- CLI shape finalized before 1.0.0: `gitcoffer gc` is report-only by
  default and deletion requires `--prune` (the `--dry-run` flag is
  gone — the default IS the dry run). `gitcoffer version --json`
  serves structured consumers, and `gitcoffer completion` emits
  scripts for bash, zsh, fish, and powershell. Installers
  (`scripts/install.sh`, `scripts/install.ps1`) download, verify, and
  install release binaries in one step.

- Final pre-1.0.0 security review (cold, full code) — all findings
  fixed: manifest reads are bounded and symlink-refusing like every
  other metadata read (a planted manifest.<n> symlink/FIFO/oversized
  file previously hung or OOM'd every operation); concurrent key
  operations re-read vault.meta under the lock so a rotation can no
  longer be silently undone by a stale snapshot; the helper surfaces
  fallback-to-older-generation instead of silently serving stale data
  (fetch warns, push refuses with the fsck remedy, and the commit
  slot-occupied error distinguishes damage from concurrency); a planted
  obj symlink no longer redirects object writes into an arbitrary host
  directory.
- Windows: a crashed holder's vault.lock is now stolen immediately —
  pid liveness is probed via OpenProcess instead of waiting out the
  staleness window (the lock message's delete guidance remains as the
  last resort). Cross-system field testing confirmed every functional
  area on Windows; the remaining field-report items were verified fixed
  in rc.2 (the LFS warning lives in the git-remote-coffer binary and
  fires before the pre-push hook; gitcoffer status warns on fallback).
  testing.
- Server-side non-fast-forward protection: a vault branch only moves to
  a descendant of its current tip unless the push is forced — unrelated
  or rewritten histories are refused with a remedy instead of silently
  overwriting the branch (the overwritten commits would be unrecoverable
  after gc). The LFS warning now fires before the pre-push hook, and
  `gitcoffer status` warns when the newest manifest generation is
  unreadable and an older one is being served.

- Cross-platform robustness gate passed: the full functional checklist
  ran twice independently on real Windows hardware and on Linux against
  the release-candidate binaries, including cross-system relay on one
  vault.
- doctor's temp-file scan covers the vault root (interrupted manifest
  writes), matching what gc sweeps — found in cross-platform field
  testing.
- Release trust chain: archives are built with the pinned toolchain
  (CGO disabled, trimpath), checksummed, the checksums signed keylessly
  (Sigstore OIDC via cosign — no stored secrets), an SBOM (spdx-json)
  attached, and GitHub build attestations recorded for every archive.
- CI hardening: race-detector and govulncheck legs, fuzz seeds for the
  untrusted-input parsers (vault.meta, manifest records, chunk framing),
  and a dedicated leg running the full suite against git 2.30 — the
  supported floor is now tested, not asserted.

- `gitcoffer export-bundle <vault> <file>` — the guaranteed exit path: a
  plain, stock-git-readable bundle of everything in the vault.
- `gitcoffer doctor <vault>` — environment and vault health check (git
  version, helper discoverability, meta shape, key-file presence,
  filesystem characteristics, leftover state).
- `gitcoffer gc` — report what would be reclaimed without deleting
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
