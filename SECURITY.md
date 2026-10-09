# Security Policy

## Reporting a vulnerability

Please report privately via GitHub's *Report a vulnerability* (the
Security tab of this repository), which notifies the maintainer without
public disclosure. If that is impossible, open a blank issue asking for
a contact and a private channel will be arranged.

Do not open a public issue describing a vulnerability — public issues are
fine for everything else (bugs, documentation gaps, hardening ideas).

Include what you can: affected component or file, a reproduction or
proof of concept, the adversary it enables (see
[docs/threat-model.md](docs/threat-model.md)), and your assessment of
severity. You will hear back within a week.

## Scope

Coffer protects repository data at rest on the vault medium; the assets,
adversaries, and explicit non-goals are defined in
[docs/threat-model.md](docs/threat-model.md). Reports within that model
— for example, ways to recover repository content from a vault without
the passphrase, or to make Coffer damage data it should not — are in
scope. The non-goals (a host compromised while the vault is open,
coercion, forgotten passphrases) are accepted by design.

## Handling

- Confirmed vulnerabilities are fixed first on a private branch and ship
  in a patch release; the advisory is published after the release with
  credit to the reporter (unless you prefer anonymity).
- The on-disk format is frozen and pinned by
  [test vectors](docs/test-vectors.json); any format-affecting fix rides
  a new format version rather than mutating v1.

## Supported versions

Only the latest release line receives fixes. Pre-releases (version
suffixes like `-pre`) are for evaluation; the vault format they write is
the frozen v1 and remains readable by future releases, but the tooling
itself is not yet supported long-term.
