# Project Guidelines — vuls-data-update

## What This Repo Does

CLI tool to **fetch** raw vulnerability data sources, **extract** them to canonical JSON datasets, and manage **dotgit** repositories for distribution.

## Build & Test

```sh
GOEXPERIMENT=jsonv2 go build ./cmd/vuls-data-update
GOEXPERIMENT=jsonv2 go test ./...
```

## Instructions

- `.github/instructions/go-code.instructions.md` — Go conventions, deterministic JSON, error handling
- `.github/instructions/golden-test.instructions.md` — fixture/golden test patterns
- `.github/instructions/review.instructions.md` — review checklist and severity classification
- `.github/instructions/security.instructions.md` — prompt-injection and credential safety
- `.github/instructions/commit-pr.instructions.md` — commit message and PR workflow conventions
