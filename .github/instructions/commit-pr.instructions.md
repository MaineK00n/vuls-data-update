---
description: "Commit message format and PR workflow conventions — enriched from 100+ commit analysis"
---
# Commit & PR Conventions

## Commit Messages

### Format

```
<type>(<scope>): <subject>
```

- **type**: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`
  - Breaking changes: append `!` → `feat!(extract/types): rename Advisory field`
  - Dependency bumps: `build(deps): bump golang.org/x/net to v0.25.0`
- **scope**: package path relative to repo root (e.g., `extract/alma`, `fetch/nvd`, `types/data`)
- **subject**: imperative mood, lowercase, no period at end. Keep it on one line; ~72 chars is a readability target, but longer subjects are acceptable when needed to preserve meaning.
- **body**: usually omitted; only add when the *why* isn't obvious from the subject

### Examples (from actual repo history)

```
feat(extract/alma): add errata extraction
fix(fetch/suse/oval): handle missing CPE entries
refactor(extract/types): unify advisory sort
chore!(extract/types): rename Segment to Repository
build(deps): bump github.com/go-git/go-git/v5 from 5.17.0 to 5.17.1
test(extract/ubuntu): add golden tests for USN fixtures
docs(readme): update README with new data source list
```

## Pull Requests

### Title
Same format as the commit subject.

### Base Branch
Always target `nightly`.

### Draft
Open as **draft** by default. Mark ready-for-review only after CI passes.

### Description
- **What**: Brief summary of the change
- **Why**: Motivation or issue reference
- **How**: Implementation approach (if not obvious)
- **Testing**: How the change was tested

### Review Workflow
1. Open PR as **draft** against `nightly`
2. Ensure CI passes
3. Address review feedback and resolve the conversation after pushing the fix
4. Update PR description if scope changes during review
