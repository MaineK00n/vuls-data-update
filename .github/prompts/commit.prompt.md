---
description: "Generate a commit message following project conventions from staged changes"
---
# /commit — Commit Message Generation

Generate a commit message for the currently staged changes.

## Procedure

Follow `.github/instructions/commit-pr.instructions.md` as the source of truth for commit message format.

1. Get staged diff: `git diff --cached`
2. Get list of staged files: `git diff --cached --name-only`
3. Run the security pre-commit checks from `.github/instructions/security.instructions.md`
4. Analyze the changes to determine:
   - **type**: feat, fix, refactor, test, docs, chore, build, ci
   - **scope**: affected package or area (e.g., `extract/alma`, `fetch/nvd`, `types`)
   - **subject**: concise description in imperative mood
5. If the change is non-trivial, add a body explaining *why* (not *what*)

## Output Format

```
<type>(<scope>): <subject>

<body>
```

## Rules

- Subject line: imperative mood, lowercase, no period. Keep it on one line; ~72 chars is a readability target, but longer subjects are acceptable when needed to preserve meaning.
- Scope: use the most specific meaningful package path
- Body: wrap at 72 chars, separate from subject with blank line
- If multiple unrelated changes are staged, suggest splitting into separate commits
