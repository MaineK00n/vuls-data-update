---
description: "Review current branch changes with structured checklist and severity classification"
---
# /review — Code Review

Review the changes in the current branch against the base branch.

## Procedure

### Phase 1: Gather Changes

1. Determine the base branch from the PR target, or default to `origin/nightly`
2. Get the diff: `git diff <base>...HEAD`
3. List changed files: `git diff --name-only <base>...HEAD`

### Phase 2: Review

For each changed file, check against the review guidelines (see `.github/instructions/review.instructions.md`).

Key areas:
- **Deterministic output**: Are `Sort()`/`Compare()` updated? Is `util.Write` used?
- **Backward compatibility**: Do type changes break external consumers?
- **Golden tests**: Are golden files updated? Are new tests added for new functionality?
- **Security**: No hardcoded secrets, input validation at boundaries, no command injection
- **Error handling**: Errors wrapped with context, consistent error patterns

### Phase 3: Classify Findings

Classify each finding by severity:
- **CRITICAL**: Must fix before merge (security, data corruption, breaking API)
- **HIGH**: Should fix (logic errors, missing error handling, test gaps)
- **MEDIUM**: Consider fixing (non-idiomatic code, missing edge cases)
- **LOW**: Optional (style, naming, minor improvements)

### Phase 4: Report

Output a structured report:

```markdown
## Review Summary

**Verdict**: APPROVE | APPROVE WITH COMMENTS | REQUEST CHANGES

### Findings

#### CRITICAL
- [ ] ...

#### HIGH
- [ ] ...

#### MEDIUM
- [ ] ...

#### LOW
- [ ] ...

### Notes
- ...
```
