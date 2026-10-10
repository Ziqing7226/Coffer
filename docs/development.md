# Development Plan

Coffer's first deliverable is the specification (this repository's docs);
code follows in the phases below. Phase scope is fixed; dates are not.

## Stack

- **Language: Go.** Static single-binary cross-compilation (linux/amd64,
  linux/arm64, windows/amd64, darwin/amd64, darwin/arm64), mature crypto
  in the standard library and
  `golang.org/x/crypto` (argon2, chacha20poly1305), and straightforward
  subprocess glue for git plumbing.
- **Dependencies stay minimal**: stdlib plus `golang.org/x/crypto` for the
  MVP; a CLI framework only if stdlib `flag` genuinely hurts.
- **git is the only runtime dependency** (unmodified). The helper shells out
  to git plumbing to move and inventory packs — `pack-objects --revs` to
  build packs in the caller repository on push, `index-pack --stdin` to
  import objects on fetch, `show-index` for inventory — rather than
  reimplementing pack handling.

## Repository layout (planned)

```text
cmd/coffer/             lifecycle CLI (init, status, rekey, gc, fsck)
cmd/git-remote-coffer/  the remote helper
internal/proto/         git remote-helper protocol (stdio framing, capabilities)
internal/vault/         on-disk format per docs/format-spec.md
internal/crypto/        key slots, DEK/KEK envelope, chunked AEAD streams
internal/packproc/      git plumbing wrappers (index-pack, show-index)
docs/                   specifications and guides
```

## Phases

### Phase 0 — Spike (days)

Prove the risky unknowns with throwaway code.

- [x] Minimal `git-remote-coffer` shim: git discovers it on PATH, `list`
      works against a plaintext directory, a push round-trips locally
      (no crypto yet).
- [x] Passphrase prompt observed through `git credential fill` — terminal
      prompt and GIT_ASKPASS paths, on Linux (branch `phase-0`).
- [x] The same prompt observed inside the VSCode UI, and on Windows and
      macOS — covered with stronger evidence later: the golden e2e suite
      drives the askpass path on all three CI operating systems, and the
      Phase 2 checklist records the by-hand VSCode pass (native input box,
      wrong passphrase, cancel).
- [ ] Windows: helper discovery from VSCode's bundled git confirmed;
      binary stdio confirmed free of CRLF issues.
- [x] Validation floor confirmed against a pinned git 2.30 build
      (container) — protocol behavior, not just compilation. Delivered
      late, in the 1.0.0 cycle: the `floor-git-230` CI leg builds
      git 2.30.0 from source and runs the full suite — and immediately
      caught the valueless option-probe incompatibility.

Exit criteria: a push initiated from VSCode reaches our code on every
supported operating system.

### Phase 1 — MVP (weeks)

- [x] Format v1 fully implemented: key slots, manifest, chunked object AEAD.
- [x] Helper capabilities: `list`, `fetch`, `push`, `option`,
      `object-format`.
- [x] `gitcoffer init` and `gitcoffer status`.
- [x] CI (GitHub Actions): unit tests plus golden protocol tests on
      ubuntu-latest, windows-latest, and macos-latest, driving real git
      clone/push/fetch against a vault.

Exit criteria: full clone → push → re-clone round-trip on every matrix
OS; `kill -9` at any write stage leaves a valid vault; a flipped byte in
any structure produces a precise error, never a panic. All three are
enforced by the e2e suite (`internal/e2e`); the Windows and macOS legs
run in CI.

### Phase 2 — Hardening

- [x] Progress reporting: `option progress` honored with stderr milestones
      on fetch and push — the channel git relays to terminals and the
      VSCode output panel.
- [x] Error messages that state what failed and what to do next.
- [x] Writer serialization: a transient `vault.lock` guards every write;
      concurrent writers queue instead of losing updates, and a crashed
      holder's lock is stolen once provably stale (format-spec §6).
- [x] `git push --atomic` and `--force-with-lease` honored end to end;
      the passphrase is approved to git after successful authentication,
      so configured credential helpers can remember it.
- [x] The insteadOf recipe documented (README, architecture notes).
- [x] Large-repository smoke test (10k commits) with timing budgets,
      opt-in via `COFFER_E2E_LARGE=1`; `COFFER_E2E_LARGE_DIR` places the
      vault on external media. Reference run on FAT32 USB media: full
      push 6.1s, fresh clone 3.4s, incremental push 3.5s, 4.9 MiB vault
      (budgets 10m / 10m / 2m). The whole e2e suite also passes with all
      vault data on FAT32 external media.
- [x] A VSCode validation pass in the UI — publishing a branch from the
      Source Control view prompts in a native input box; a wrong
      passphrase surfaces the actionable error including the eviction
      recipe; canceling the prompt reports the empty credential.
      Validated by hand in VSCode 1.140 on Linux.

### Phase 3 — Key management

- [x] Multiple key slots; `gitcoffer rekey` rewrites only `vault.meta` —
      tests assert object files stay byte-identical.
- [x] Optional key file as a second factor: the slot derives from
      passphrase + key-file bytes and records the path, so the helper
      reads it automatically (no per-remote configuration).
- [x] `gitcoffer gc` (orphaned objects, `.tmp` sweep, generation pruning;
      holds the writer lock across scan and sweep; refuses to delete
      anything if any generation fails to decrypt) and `gitcoffer fsck`
      (slot shapes, manifest authentication, `prev` chain, ref inventory,
      per-object AEAD + checksum + size; first divergence per structure).

### Phase 4 — v1.0

- [x] Release binaries: a tag-driven release workflow builds six targets
      (linux/amd64+arm64, windows/amd64+arm64, darwin/amd64+arm64) with
      checksums and publishes the GitHub release; scoop, winget, and
      Homebrew manifests are prepared under `packaging/` for submission
      with the stable 1.0.0.
- [x] User guide pages — [user-guide.md](user-guide.md): install,
      quickstart, keys and recovery, maintenance, troubleshooting; the
      README carries the quick start and a CLI reference.
- [x] Security review of the crypto envelope and error paths; format v1
      frozen as stable. A self-review covered the KDF/AEAD envelope, AAD
      bindings and nonce bounds, error and credential paths (passphrases
      never cross argv or logs), the filesystem attack surface, and every
      recovery path; an independent review followed — three cold reviewers
      with no prior context (cryptography, Go application security, git
      protocol and backup integrity) auditing from the repository alone.
      Their confirmed findings are fixed with regression tests: unbounded
      reads of untrusted metadata paths (a planted key-file path or lock
      symlink aimed at /dev/zero would read forever), crafted vault.meta
      shapes (non-hex ids enabling paste-injection hints, slot floods,
      oversized headers), future-dated planted locks blocking writes past
      their stated date, undetected append-tampering of object files, and
      test vectors not pinning the Argon2id parameters — plus three from
      the protocol reviewer: pushing from a sha256 repository stored
      history the vault could never serve back (now refused in both
      directions), pushing from a shallow clone silently stored truncated
      history and poisoned later incremental pushes (now refused with an
      unshallow remedy), and an --atomic batch with a failed ref reported
      the other refs as ok without committing anything (the whole batch
      now reports error); a commit-time generation-exists check narrows
      the stolen-lock race window, meta rewrites take the writer lock and
      use unpredictable temp names, and the scratch environment also drops
      GIT_COMMON_DIR. One confirmed vulnerability fixed: predictable temp-file names
      let an attacker with brief write access to the medium plant symlinks
      turning the next write into an arbitrary-file replacement on the
      host — now refused via O_NOFOLLOW, regression-tested. Conformance
      test vectors published (docs/test-vectors.json) and re-verified on
      every test run.
- [x] Disk-full robustness: `TestDiskFullRobustness` (opt-in,
      `COFFER_E2E_FULL=1`) re-executes itself inside an unprivileged user
      namespace with a 1 MiB tmpfs as the vault medium and sweeps the free
      space upward. Observed: ENOSPC refusing pushes at three different
      layers (lock file, mid-object, mid-manifest), every refusal leaving
      the one-consistent-state invariant intact, a failed rekey leaving
      the old passphrase working, and full recovery once space returns
      (push, gc, fsck clean, byte-matching clone). No root or real disk
      needed; a FAT loop-device variant would need privileges and is
      optional.

## Toward 1.0.0 (gated work plan)

The stable tag must be mature enough to earn trust, so every maturity
item lands BEFORE 1.0.0 and the release candidate gates on real
dual-platform testing. The flow: finish the maturity batch, cut rc.2,
run the full checklist on real Windows hardware and Linux, and only
then cut 1.0.0.

**Done:**

- [x] Independent security review — three cold reviewers (cryptography,
      Go application security, git protocol and backup integrity); all
      confirmed findings fixed with regression tests.
- [x] Disk-full robustness — user-namespace tmpfs suite.
- [x] Release trust chain live on published assets: keyless Sigstore
      signature, SBOM (spdx-json), build attestations, checksums; the
      linux-amd64 archive and its checksum verified end to end with
      cosign.
- [x] Security policy, export-bundle, doctor, LFS warning, support
      matrix, "What Coffer is not", changelog.
- [x] Golden vault fixture, corruption matrix expansion, CI hardening
      (`go test -race`, govulncheck, git 2.30 floor leg, fuzz seeds).
- [x] Server-side non-fast-forward protection (from the Windows field
      report — the data-loss risk).
- [x] GitCoffer rename and branch hygiene: all merged working branches
      deleted; main is the line of development.
- [x] v1.0.0-rc.1 published and verified end to end.

**The 1.0.0 maturity batch (lands before rc.2):**

- [x] `gitcoffer version --json` for structured consumers.
- [x] gc CLI finalized: report-only by default, real deletion requires
      `--prune` (the 1.0.0 window is the last chance to settle the CLI
      shape).
- [ ] Shell completions (bash, zsh, fish, powershell).
- [ ] install.sh / install.ps1 that verify checksums and the release
      signature.
- [ ] A final cold security review over the complete 1.0.0 code — the
      earlier round predates export-bundle, doctor, non-fast-forward
      protection, and the gc shape.

**The gate:**

- [ ] v1.0.0-rc.2 published.
- [ ] Dual-platform robustness pass: the full functional checklist
      (init, push/pull/clone incl. non-default branches, doctor,
      export-bundle, gc --prune, rekey with credential eviction, key
      files, wrong-passphrase handling, corruption handling, LFS
      pointer behavior, cross-system relay) passes on real Windows
      hardware AND on Linux against rc.2.
- [ ] Stable 1.0.0, then store submissions with real hashes (the scoop
      and Homebrew repos exist; manifests in `packaging/` take the
      released hashes; winget ships as a PR from the maintainer's
      fork).

Deliberately deferred PAST 1.0.0 — recorded so the deferral is a
decision, not an omission:

- **gc repacking.** Every push writes one object file holding only the
  new objects, and the manifest carries the full inventory forward —
  manifest size and clone time grow with push count. Repacking would
  consolidate object files behind the same crash-safe ordering. It is
  a data-path optimization and is safer with real-world data
  accumulated.
- **Binding the manifest generation into the AAD (format v2).** A
  medium-holder who kept an old manifest file can re-file it under a
  higher generation (rollback); today fsck's chain check exposes this,
  but authentication itself would reject it if the generation were part
  of the AAD. That is a format change and v1 is frozen.
- VSCode companion extension, CI performance budgets, an ADR directory.

Deliberately declined: per-run CI performance budgets as failures
(flaky), a formal ADR directory (decisions live in the spec and
architecture notes), and a comparison page (replaced by the neutral
"Choosing an approach").

## Testing strategy

- **Golden protocol tests** drive real `git` end-to-end: create a scratch
  repository, add the coffer remote, push, clone elsewhere, compare. These
  are the highest-value tests in the project.
- **Fault injection**: a test hook aborts the helper at each named write
  stage; every abort point must leave a vault that opens and passes fsck.
- **Corruption matrix**: flip a byte in every structure type (meta slot,
  manifest, chunk header, chunk body, chunk tag) and assert the exact error.
- **Crypto conformance**: fixed test vectors for the key-slot envelope and
  chunk framing, published with the reference implementation.
- **Media validation**: the e2e suite passes with `TMPDIR` on FAT32
  external media (`GOTMPDIR` keeps build artifacts on an executable
  filesystem); vaults and scratch repositories then exercise a
  permission-less, case-insensitive filesystem end to end.
- **Git version matrix**: the validation floor (git 2.30, the first release
  with the helper `object-format` capability) and current git, across all
  supported operating systems. The exact versions exercised per release are
  the ones in the CI runs for that release tag — public, never asserted by
  hand.

## Conventions

- All artifacts in English — see CONTRIBUTING.md; reviews treat it as a
  hard requirement.
- Conventional Commits (`docs:`, `feat:`, `fix:`, `test:`, `refactor:`).
- `gofmt` / `golangci-lint` clean; no generated files committed.
- Specification changes go through a PR that bumps the relevant version
  field. The format specification is normative: code is reviewed against the
  spec, not against another implementation's behavior.
