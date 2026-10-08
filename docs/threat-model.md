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
how large the repository is. Concealing this through padding or cover
traffic is deliberately out of scope for v1.

## Cryptographic assumptions

Standard assumptions about Argon2id, XChaCha20-Poly1305, and the OS CSPRNG;
no novel construction is used. Parameter guidance lives in the
[format specification](format-spec.md). Should a primitive need replacing,
the versioned key-slot design is the migration path: new slots can carry new
algorithms alongside old ones during transition.
