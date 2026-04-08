# CLAUDE.md — vuls-data-update

## What This Repo Does

CLI tool to **fetch** raw vulnerability data sources, **extract** them to canonical JSON datasets, and manage **dotgit** repositories for distribution.

## Build & Test

```sh
go build ./cmd/vuls-data-update
go test ./...
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
- **Sort/Compare**: `Sort()` recursively normalizes nested slices — no need to pre-sort map keys
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

## Sync (.github/instructions/ → .claude/rules/)

After editing `.github/instructions/*.instructions.md`, regenerate `.claude/rules/`:

```sh
mkdir -p .claude/rules
for f in .github/instructions/*.instructions.md; do
  base=$(basename "$f" .instructions.md)
  awk 'NR==1 && $0=="---" { in_front_matter=1; next } in_front_matter && $0=="---" { in_front_matter=0; next } !in_front_matter { print }' "$f" > ".claude/rules/$base.md"
done
```
