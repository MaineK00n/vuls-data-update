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
- **Golden tests**: Fixtures in `testdata/fixtures/`, golden output in `testdata/golden/`. Use `util/test` helpers
- **Cleanup**: Use `util.RemoveAll(dir)` — preserves `README.md` and `.git`
- **Cache**: `util.CacheDir()` defaults to `~/.cache/vuls-data-update`

## Rules & Docs

Files under `.claude/rules/` are **generated** from `.github/instructions/` — do not edit them directly.

- Coding: `.claude/rules/go-code.md`
- Golden tests: `.claude/rules/golden-test.md`
- Review: `.claude/rules/review.md`
- Git workflow: `.claude/rules/commit-pr.md`
- Security: `.claude/rules/security.md`

## Sync & Validation

After editing `.github/instructions/*.instructions.md`, regenerate `.claude/rules/`:

```sh
make sync-rules
```

Validate the harness as a whole with:

```sh
make check-harness
```

`check-harness` aggregates:

- `check-rules` — `.claude/rules/` matches `.github/instructions/`
- `check-shims` — every `.github/prompts/<name>.prompt.md` has a `.claude/skills/<name>/SKILL.md`; every `.github/agents/<name>.agent.md` has a `.claude/agents/<name>.md`
- `check-docs` — `CLAUDE.md` and `AGENTS.md` share an identical "What This Repo Does" + "Build & Test" intro (the first two `##` sections)

These targets use bash.
