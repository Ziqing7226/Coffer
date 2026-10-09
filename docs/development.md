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
- [ ] Validation floor confirmed against a pinned git 2.30 build
      (container) — protocol behavior, not just compilation.

Exit criteria: a push initiated from VSCode reaches our code on every
supported operating system.

### Phase 1 — MVP (weeks)

- [x] Format v1 fully implemented: key slots, manifest, chunked object AEAD.
- [x] Helper capabilities: `list`, `fetch`, `push`, `option`,
      `object-format`.
- [x] `coffer init` and `coffer status`.
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

- [x] Multiple key slots; `coffer rekey` rewrites only `vault.meta` —
      tests assert object files stay byte-identical.
- [x] Optional key file as a second factor: the slot derives from
      passphrase + key-file bytes and records the path, so the helper
      reads it automatically (no per-remote configuration).
- [x] `coffer gc` (orphaned objects, `.tmp` sweep, generation pruning;
      holds the writer lock across scan and sweep; refuses to delete
      anything if any generation fails to decrypt) and `coffer fsck`
      (slot shapes, manifest authentication, `prev` chain, ref inventory,
      per-object AEAD + checksum + size; first divergence per structure).

### Phase 4 — v1.0

- [ ] Release binaries (linux/amd64, linux/arm64, windows/amd64,
      darwin/amd64, darwin/arm64); scoop, winget, and Homebrew packaging.
- [ ] User guide pages (quickstart, install, keys and recovery) — written
      together with the code, not before.
- [x] Security review of the crypto envelope and error paths; format v1
      frozen as stable. A self-review (independent review welcome before
      the 1.0 release) covered the KDF/AEAD envelope, AAD bindings and
      nonce bounds, error and credential paths (passphrases never cross
      argv or logs), the filesystem attack surface, and every recovery
      path. One confirmed vulnerability fixed: predictable temp-file names
      let an attacker with brief write access to the medium plant symlinks
      turning the next write into an arbitrary-file replacement on the
      host — now refused via O_NOFOLLOW, regression-tested. Conformance
      test vectors published (docs/test-vectors.json) and re-verified on
      every test run.

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
  supported operating systems. Tested versions are recorded per release,
  sourced from the CI matrix — never asserted by hand.

## Conventions

- All artifacts in English — see CONTRIBUTING.md; CI enforces it on changed
  files.
- Conventional Commits (`docs:`, `feat:`, `fix:`, `test:`, `refactor:`).
- `gofmt` / `golangci-lint` clean; no generated files committed.
- Specification changes go through a PR that bumps the relevant version
  field. The format specification is normative: code is reviewed against the
  spec, not against another implementation's behavior.
