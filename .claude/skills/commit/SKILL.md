---
name: commit
description: "Generate a commit message following project conventions from staged changes"
---
# /commit — Commit Message Generation

**You MUST use the Read tool on `.github/prompts/commit.prompt.md` before doing anything else, and follow that file's procedure verbatim. It is the authoritative specification for this skill — the summary below is a reminder, not a substitute. Do not produce a commit message until you have read it.**

## Quick Reference (reminder; not a substitute for the prompt file)
- `/commit` — generate commit message from staged changes
- Format: `<type>(<scope>): <subject>`
- Types: feat, fix, refactor, test, docs, chore, build, ci
- Imperative mood, lowercase, no trailing period
- Suggests splitting if multiple unrelated changes are staged
