# Contributing to Coffer

Thanks for helping. Coffer is a security tool: clarity beats cleverness, and
the specifications are contracts.

## Iron Rule — English only

Every artifact produced in this repository — code, comments, documentation,
commit messages, issues, pull request descriptions, and release notes — must
be written entirely in English. No exceptions, no mixed language. CI
enforces this on changed files.

## Before you invest time

- **Now:** the best contributions are issues that find holes, ambiguities,
  or over-engineering in the documentation and implementation, and pull
  requests that fix them.
- **Implementation work:** code follows docs/development.md. Check that the
  relevant phase is active before proposing implementation, and open an
  issue first for anything not already covered by one.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`), one
logical change per commit, imperative subject line, body explaining the
*why*.

## Pull request checklist

- [ ] English only (see above).
- [ ] Tests cover the change, and golden protocol tests pass on Linux,
      Windows, and macOS (once the code phases are active).
- [ ] Behavior-affecting change: docs/format-spec.md or docs/architecture.md
      updated in the same PR, with version fields bumped where applicable.
- [ ] No real names, personal paths, or machine-specific details anywhere.
