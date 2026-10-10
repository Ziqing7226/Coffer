# AGENTS.md

Guide for AI agents (and humans in a hurry) working in this repository.

## What this is

Coffer is an encrypted git remote: a remote helper (`git-remote-coffer`)
that lets unmodified git push to and clone from a passphrase-protected vault
directory on a secondary or removable disk. Linux, Windows, and macOS are
first-class; VSCode works because git works.

**Current state: v1.0.0-rc.3 released, stable 1.0.0 pending the final
security round** — vault format v1 (frozen, pinned by
docs/test-vectors.json), the `git-remote-coffer` helper (progress
milestones, writer lock, `--atomic`/`--force-with-lease`, server-side
non-fast-forward protection, credential approval, HEAD fallback for
non-main repositories), the `gitcoffer` CLI (init, status, key
add/remove/list, rekey, gc report-only with --prune, fsck, doctor,
export-bundle, version --json, completion), CI on Linux, Windows, and
macOS plus a git 2.30 floor leg, three independent security review
rounds complete, release workflow (six platforms) and packaging
manifests under `packaging/`, and the user guide. The stable tag
follows the final review round and device-variety testing.
docs/development.md tracks the gate.

## Iron Rule — English only

> Every artifact produced in this repository — code, comments, documentation,
> commit messages, issues, pull request descriptions, and release notes —
> must be written entirely in English. No exceptions, no mixed language.

## Routing

| Need | Read |
|---|---|
| Design rationale, components, protocol flows | docs/architecture.md |
| On-disk format (normative) | docs/format-spec.md |
| Security boundaries | docs/threat-model.md |
| Phases, testing strategy, conventions | docs/development.md |
| Contribution rules, commit style | CONTRIBUTING.md |

## Working rules for agents

- Build against the format specification, not against another
  implementation's behavior; if they conflict, the spec wins and an issue
  should be filed.
- Never commit real names, personal paths, machine-specific details, or
  narrative background. Examples use generic paths (`/mnt/usb/…`,
  `D:\backups\…`).
- Follow Conventional Commits; one logical change per commit.
- Do not renumber or move docs/ files; link by relative path.
- Build and test: `go build ./...`, `go vet ./...`, `go test ./...`. The
  e2e package drives real git and builds the binaries itself; git must be
  on PATH. Fault injection uses the COFFER_CRASH environment variable
  (internal/vault crash points).
