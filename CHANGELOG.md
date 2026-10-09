# Changelog

## Unreleased (toward 1.0.0)

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
- `gitcoffer gc --dry-run` — report what would be reclaimed without
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
