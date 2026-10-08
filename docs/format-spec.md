# Vault Format Specification (v1)

Status: **draft — normative for Phase 1.** The key words MUST, MUST NOT,
SHOULD, and MAY are to be interpreted as described in RFC 2119. This
document is the single source of truth for the on-disk format; any change to
the format requires bumping `format_version`.

## 1. Overview

A vault is a plain directory. Everything git needs — objects and refs — is
stored as AEAD-encrypted files. Nothing in the vault reveals repository
content, ref names, or object identifiers.

```text
myproject.coffer/
├── vault.meta            # plaintext header: format version, vault id, key slots
├── manifest.<n>          # DEK-encrypted index: refs, pack inventory, chain
└── obj/
    └── <hex>             # encrypted pack chunks (immutable once written)
```

All multi-byte integers are big-endian. Strings are UTF-8. Binary values
inside JSON are base64 (RFC 4648, padded) and written as `<b64>` below.

## 2. Primitives

| Purpose | Primitive |
|---|---|
| Key derivation | Argon2id |
| AEAD | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) |
| Randomness | OS CSPRNG |

Recommended Argon2id defaults for new slots: memory 64 MiB, iterations 3,
parallelism 4. Implementations MUST honor the parameters stored in a slot
and MAY refuse parameters above implementation-defined ceilings.

Every AEAD operation binds additional authenticated data:

```text
AAD = "coffer/" + format_version + "/" + role + "/" + role_specific_id
```

with `role` ∈ {`meta-slot`, `manifest`, `obj-chunk`}. Examples below show
only the `role` and `role_specific_id` parts, omitting the constant
`coffer/<format_version>/` prefix. Implementations MUST verify the AAD
exactly; a ciphertext moved between vaults, roles, or positions MUST fail
authentication.

## 3. `vault.meta` (plaintext)

A single JSON object, created by `coffer init`, rewritten only by
`coffer rekey` — in both cases atomically (§6).

```json
{
  "format_version": 1,
  "id": "<32 hex: random 16-byte vault identity, assigned at init>",
  "created": "2026-10-08T00:00:00Z",
  "slots": [
    {
      "id": 0,
      "kdf": {
        "algo": "argon2id", "m": 65536, "t": 3, "p": 4,
        "salt": "<b64, 16 bytes>"
      },
      "aead": { "algo": "xchacha20-poly1305", "nonce": "<b64, 24 bytes>" },
      "dek": "<b64: AEAD(plaintext = DEK, key = KEK, nonce, AAD(\"meta-slot/<vault id>/<slot id>\"))>"
    }
  ]
}
```

Rules:

- Readers MUST refuse an unknown `format_version`. Version 1 is exactly the
  value `1`.
- There MUST be at least one slot. Multiple slots allow several passphrases
  or key files to open the same vault.
- Slot `id` values are stable identifiers; `rekey` rewrites the whole file.
- The KEK is `Argon2id(passphrase, salt, m, t, p)` for the slot's stored
  parameters. A slot succeeds if and only if its `dek` field authenticates.

## 4. Manifest (encrypted)

Manifests are numbered files `manifest.<n>` with monotonically increasing
`n`. Each is:

```text
24-byte random nonce || AEAD(JSON payload, DEK, nonce, AAD("manifest/<vault id>"))
```

Payload schema:

```json
{
  "version": 1,
  "generated": "2026-10-08T00:00:00Z",
  "prev": "<64 hex: SHA-256 of the previous manifest's plaintext payload, or null for the first>",
  "refs": {
    "refs/heads/main": { "oid": "<40 or 64 hex>", "peeled": "<hex or null>" }
  },
  "packs": {
    "<file name in obj/>": {
      "sha256": "<64 hex: SHA-256 of the plaintext pack>",
      "size": 1048576,
      "objects": ["<object ids contained in this pack>"]
    }
  },
  "generations": { "kept": 2 }
}
```

Rules:

- The effective state is the highest-numbered manifest that authenticates.
  Readers MUST ignore `.tmp` files and older generations except for chain
  verification.
- `prev` chains manifests so that interrupted or reordered history is
  detectable by `coffer fsck`. A vault opens as long as the newest manifest
  authenticates; the chain is a diagnostic, not a gate.
- `refs` uses fully qualified refnames. Deleting a ref is simply a manifest
  rewrite without it.
- `packs[file].objects` is the authoritative object inventory; an object MAY
  appear in more than one pack (reconciliation is a `gc` concern, not a
  format constraint).
- `generations.kept` bounds how many manifest generations are retained
  (default 2).

## 5. Object files (`obj/`)

An object file holds one plaintext packfile, encrypted as independent
fixed-size chunks:

```text
file name  = 32 hex chars from the CSPRNG (16 bytes); no content is derivable from it
CHUNK      = 64 MiB of plaintext
chunk_k    = nonce_k (24 bytes) || AEAD(plaintext[k*CHUNK .. min(size, (k+1)*CHUNK)),
                                       DEK, nonce_k,
                                       AAD("obj-chunk/<vault id>/<file name>/<k>"))
file       = chunk_0 || chunk_1 || …
```

- Object files are immutable once committed. They are removed only by
  `coffer gc`, never rewritten.
- `packs[file].size` in the manifest determines the plaintext length and
  therefore the chunk count; no length prefixes appear in the file.
- Chunking at 64 MiB bounds memory, enables streaming, and localizes damage:
  a corrupted chunk fails exactly itself, and the remaining chunks still
  authenticate.

## 6. Write ordering and crash safety

Writers MUST persist with this ordering:

1. **Object files**: write to `obj/<name>.tmp`, fsync the file, rename to
   `obj/<name>`, fsync the directory.
2. **Manifest**: write to `manifest.<n+1>.tmp`, fsync, rename to
   `manifest.<n+1>`, fsync the directory, then unlink generations older
   than `generations.kept` allows.
3. **`vault.meta`** (init/rekey only): same temp–fsync–rename–fsync pattern.

A crash at any point leaves either the previous state or the new state —
never a mixture. Any `.tmp` file a reader finds is garbage by definition;
`gc` sweeps it.

## 7. Corruption and tamper semantics

- AEAD failure on any structure is a hard error naming the file and chunk;
  implementations MUST NOT attempt recovery by re-deriving or guessing.
- `coffer fsck` verifies every AEAD, the `prev` chain, the ref inventory,
  and pack checksums, and reports the first divergence per structure.

## 8. Test vectors

Conformance vectors for the key-slot envelope and chunk framing will be
published alongside the reference implementation in Phase 1; until then this
document alone defines correctness.
