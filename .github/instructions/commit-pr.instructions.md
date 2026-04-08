---
description: "Commit message format and PR workflow conventions — enriched from 100+ commit analysis"
---
# Commit & PR Conventions

## Commit Messages

### Format

```
<type>(<scope>): <subject> (#PR_NUMBER)
```

- **type**: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`
  - Breaking changes: append `!` → `feat!(extract/types): rename Advisory field`
  - Dependency bumps: `build(deps): bump golang.org/x/net to v0.25.0`
- **scope**: package path relative to repo root (e.g., `extract/alma`, `fetch/nvd`, `types/data`)
- **subject**: imperative mood, lowercase, no period at end
- **body**: usually omitted; only add when the *why* isn't obvious from the subject

### Examples (from actual repo history)

```
feat(extract/alma): add errata extraction (#174)
fix(fetch/suse/oval): handle missing CPE entries (#640)
refactor(extract/types): unify advisory sort (#694)
chore!(extract/types): rename Segment to Repository (#708)
build(deps): bump github.com/go-git/go-git/v5 from 5.17.0 to 5.17.1 (#737)
test(extract/ubuntu): add golden tests for USN fixtures (#693)
docs: update README with new data source list (#750)
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
3. Address review feedback — post `fixed: <commit-url>` when addressing specific comments
4. Update PR description if scope changes during review
