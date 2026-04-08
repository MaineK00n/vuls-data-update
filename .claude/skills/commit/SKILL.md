---
name: commit
description: "Generate a commit message following project conventions from staged changes"
---
# /commit — Commit Message Generation

> **Full specification**: See `.github/prompts/commit.prompt.md`

## Quick Reference
- `/commit` — generate commit message from staged changes
- Format: `<type>(<scope>): <subject>`
- Types: feat, fix, refactor, test, docs, chore, ci
- Imperative mood, lowercase, no trailing period
- Suggests splitting if multiple unrelated changes are staged
