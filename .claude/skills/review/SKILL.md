---
name: review
description: "Code review with structured checklist and severity classification"
---
# /review — Code Review

**You MUST use the Read tool on `.github/prompts/review.prompt.md` before doing anything else, and follow that file's Phase 1–4 procedure verbatim — including loading every instruction file it lists in Phase 2 (`review.instructions.md`, `go-code.instructions.md`, `golden-test.instructions.md`, `security.instructions.md`). It is the authoritative specification for this skill — the summary below is a reminder, not a substitute. Do not produce a review until you have read all of them.**

## Quick Reference (reminder; not a substitute for the prompt file)
- `/review` — review current branch changes against base
- Phase 1: gather diff and changed files
- Phase 2: review against checklist (determinism, compatibility, security, tests)
- Phase 3: classify findings by severity (CRITICAL/HIGH/MEDIUM/LOW)
- Phase 4: output structured report with verdict (APPROVE / APPROVE WITH COMMENTS / REQUEST CHANGES)
