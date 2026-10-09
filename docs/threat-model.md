# Threat Model

Coffer keeps a private, complete, off-disk copy of a git repository on media
that may be lost or examined. This document defines what protection means —
and, as importantly, what it does not.

## Assets

- Repository content: commits, trees, blobs, ref names, and history — in
  short, everything an unencrypted bare remote would expose.
- Backup integrity: corruption or tampering with vault files must be
  detected, never silently decrypted around.

## Trust boundaries

- **The host is trusted while a coffer operation is running.** The plaintext
  repository, the passphrase, and the data key exist in host memory, and the
  working copy lives in plaintext on the host disk — as with any git use.
- **The vault medium is untrusted at rest.** Anyone may hold, read, copy, or
  image the external disk at any time outside an open session.

## Adversaries in scope

1. **Finder or thief of the medium.** Sees random-looking files and faces
   Argon2id key derivation with no shortcut.
2. **Forensic imaging** (confiscation, border search). Equivalent to the
   above: no authenticated metadata exists on the medium.
3. **Degraded media.** Bit-rot and partial writes are caught by AEAD
   authentication and reported precisely; nothing is guessed around.
4. **Failure of the original working disk.** The vault is a *complete*
   remote: vault plus passphrase reconstruct the repository on a fresh
   machine with `git clone coffer::…`.

## Adversaries out of scope

- **A compromised host during use.** Malware running with the user's
  privileges can read the plaintext repository and intercept the
  passphrase. No at-rest encryption tool can help; this boundary is
  accepted and stated plainly.
- **Coercion.** The passphrase is the boundary; Coffer provides no
  deniability and no hidden-volume features.
- **A forgotten passphrase.** No recovery exists, by design. A key file may
  add a second factor, never a rescue.
- **A malicious writer with sustained access to the medium.** An attacker
  able to rewrite the entire vault at will can roll it back to an earlier
  consistent generation. Retaining several manifest generations
  (`generations.kept`, default 2) makes rollback *visible* to
  `coffer fsck` when compared against remembered state, but Coffer does not
  provide trusted timestamping.

## Metadata leakage (known, accepted)

An observer of the medium learns the number of files, their sizes (a
multiple of the chunk size), and write timestamps — roughly how active and
how large the repository is. Two more items are readable in `vault.meta`
and the transient writer lock: a second-factor slot records its key
file's path (potentially a host path revealing a username), and
`vault.lock` names the writing host while an operation runs (removed at
its end; a crashed writer's lock persists until the staleness window
passes). Concealing any of this through padding or cover traffic is
deliberately out of scope for v1.

## Local filesystem hardening

Temp files inside the vault directory have predictable names
(`vault.meta.tmp`, `manifest.<n>.tmp`), so an attacker with brief write
access to the medium could plant symlinks meant to turn the next write
into an arbitrary-file replacement on the host. Coffer refuses to write
through planted links on Unix (`O_NOFOLLOW`: the operation fails and the
symlink's target stays untouched). On Windows, where creating symlinks
requires developer mode or elevated privileges, the plain create remains
the baseline.

Reads of untrusted metadata are bounded the same way: a key-file path or
lock file planted as a symlink, device, or FIFO is refused instead of
read, with size caps (1 MiB for key files and vault.meta, 8 KiB for the
lock), and vault.meta is rejected outright unless its id is the
spec-defined 32 hex characters and it carries at most 16 key slots — a
planted header cannot make the open path grind through unbounded
Argon2id work or aim the reader at endless files. A planted lock dated
in the future blocks writes at most one staleness window, never until
its stated date.

## Cryptographic assumptions

Standard assumptions about Argon2id, XChaCha20-Poly1305, and the OS CSPRNG;
no novel construction is used. Parameter guidance lives in the
[format specification](format-spec.md), which also publishes conformance
test vectors pinning the exact byte layout of every sealed structure.
Should a primitive need replacing,
the versioned key-slot design is the migration path: new slots can carry new
algorithms alongside old ones during transition.

Two design choices worth recording: a second-factor slot's KDF input is the
passphrase concatenated with the key-file bytes (spec §3) — the
concatenation is unambiguous in practice because a slot's salt is random,
so an ambiguous split would still have to reproduce the exact slot; and
random 192-bit XChaCha20 nonces make nonce collision a non-concern at any
plausible chunk or manifest count.
