# AGENTS.md

Guide for AI agents (and humans in a hurry) working in this repository.

## What this is

Coffer is an encrypted git remote: a remote helper (`git-remote-coffer`)
that lets unmodified git push to and clone from a passphrase-protected vault
directory on a secondary or removable disk. Linux and Windows are
first-class; VSCode works because git works.

**Current state: specification phase.** Documentation only — no code yet.
The most useful contributions right now sharpen the specification;
implementation begins with Phase 0 (see docs/development.md).

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
- There are no build or test commands yet — code arrives in Phase 0. Do not
  add CI or README claims that suggest otherwise.
