---
description: "Generate a commit message following project conventions from staged changes"
---
# /commit — Commit Message Generation

Generate a commit message for the currently staged changes.

## Procedure

1. Get staged diff: `git diff --cached`
2. Get list of staged files: `git diff --cached --name-only`
3. Analyze the changes to determine:
   - **type**: feat, fix, refactor, test, docs, chore, ci
   - **scope**: affected package or area (e.g., `extract/alma`, `fetch/nvd`, `types`)
   - **subject**: concise description in imperative mood
4. If the change is non-trivial, add a body explaining *why* (not *what*)

## Output Format

```
<type>(<scope>): <subject>

<body>
```

## Rules

- Subject line: imperative mood, lowercase, no period, max 72 chars
- Scope: use the most specific meaningful package path
- Body: wrap at 72 chars, separate from subject with blank line
- If multiple unrelated changes are staged, suggest splitting into separate commits
