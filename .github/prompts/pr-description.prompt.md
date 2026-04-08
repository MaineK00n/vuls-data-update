---
description: "Generate or update a PR description from the current branch changes"
---
# /pr-description — PR Description Generation

Generate a PR description for the current branch.

## Procedure

1. Get branch name: `git branch --show-current`
2. Get commits on this branch: `git log --oneline origin/nightly..HEAD`
3. Get full diff: `git diff origin/nightly...HEAD --stat`
4. For complex changes, read the actual diff to understand the intent

## Output Format

```markdown
## What

Brief summary of the change.

## Why

Motivation, issue reference, or context.

## How

Implementation approach (if not obvious from the diff).

## Testing

How the change was tested:
- `go test ./...`
- Specific test commands or manual verification steps

## Checklist

- [ ] Tests pass
- [ ] Golden files updated (if applicable)
- [ ] Deterministic output verified (if types changed)
- [ ] Backward compatibility maintained (if types/data changed)
```

## Rules

- Keep the description concise but informative
- Link related issues if branch name contains an issue number
- If the PR modifies extracted types, explicitly note backward compatibility impact
