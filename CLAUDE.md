# CLAUDE.md — vuls-data-update

## What This Repo Does

CLI tool to **fetch** raw vulnerability data sources, **extract** them to canonical JSON datasets, and manage **dotgit** repositories for distribution.

## Build & Test

```sh
GOEXPERIMENT=jsonv2 go build ./cmd/vuls-data-update
GOEXPERIMENT=jsonv2 go test ./...
```

## Architecture

- **Cobra command tree**: Root in `pkg/cmd/root/root.go` → `fetch`, `extract`, `dotgit`
- **Data-source subcommands**: Registered in switchboards at `pkg/cmd/fetch/fetch.go` and `pkg/cmd/extract/extract.go`
- **Adding a new data source**:
  1. Implement fetcher in `pkg/fetch/<domain>/<name>/`
  2. Implement extractor in `pkg/extract/<domain>/<name>/`
  3. Wire `newCmd…()` in both `pkg/cmd/fetch/fetch.go` and `pkg/cmd/extract/extract.go`
  4. Follow the pattern of `newCmdAlmaErrata()`

## Key Conventions

- **Deterministic JSON**: Use `encoding/json/v2` with `json.Deterministic(true)` and tab indent via `util.Write()`
- **Sort/Compare**: `Sort()` recursively normalizes nested slices; map key ordering is provided by `json.Deterministic(true)` during encoding
- **Golden tests**: Fixtures in `testdata/fixtures/`, golden output in `testdata/golden/`. Use `pkg/extract/util/test` helpers
- **Cleanup**: Use `util.RemoveAll(dir)` — preserves `README.md` and `.git`
- **Cache**: `util.CacheDir()` defaults to `<os.UserCacheDir()>/vuls-data-update` (with a temp-dir fallback)

## Rules & Docs

`.claude/rules/` and `.github/instructions/` mirror each other for different agent ecosystems (Claude Code / Copilot). When editing one side, try to keep the other roughly in sync — exact parity is a best-effort goal, since the two ecosystems differ in minor format details.

- Coding: `.claude/rules/go-code.md`
- Golden tests: `.claude/rules/golden-test.md`
- Review: `.claude/rules/review.md`
- Git workflow: `.claude/rules/commit-pr.md`
- Security: `.claude/rules/security.md`
