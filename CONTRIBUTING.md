# Contributing to BountyCompass

Thanks for considering a contribution. This repo works best as a living, community-checked reference, so improvements are genuinely useful.

## What's welcome

- New checks/payloads for existing categories (auth, IDOR, injection, etc.)
- Corrections to outdated or inaccurate techniques
- Clearer explanations of *why* a check works, not just the payload
- New sections for vulnerability classes not yet covered (SSRF, GraphQL-specific abuse, cloud misconfig, etc.)
- Tooling notes (better alternatives to a listed tool, flags that improve signal-to-noise)

## What to avoid

- Live, working exploits against real, named, non-consenting targets
- Anything that only works as a weaponized/automated attack tool rather than a documented technique
- Duplicate content — check existing docs first

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b add-graphql-checklist`
3. Make your changes under `docs/` (or propose a new file if it doesn't fit an existing section)
4. Keep formatting consistent with existing docs (headers, tables, fenced code blocks, "why this works" notes)
5. Open a pull request with a short description of what you added/changed and why

## Style notes

- Prefer tables for payload lists (payload → what it targets)
- Every technique should say **why** it works, not just what to paste
- Mark destructive/active techniques clearly (writes to the target, brute-force, etc.)
