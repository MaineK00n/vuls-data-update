---
name: review
description: "Code review with structured checklist and severity classification"
---
# /review — Code Review

> **Full specification**: See `.github/prompts/review.prompt.md`

## Quick Reference
- `/review` — review current branch changes against base
- Phase 1: gather diff and changed files
- Phase 2: review against checklist (determinism, compatibility, security, tests)
- Phase 3: classify findings by severity (CRITICAL/HIGH/MEDIUM/LOW)
- Phase 4: output structured report with verdict (APPROVE / APPROVE WITH COMMENTS / REQUEST CHANGES)
