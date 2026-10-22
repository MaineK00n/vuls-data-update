# vuls-data-update

CLI tool to **fetch** raw vulnerability data sources, **extract** them to canonical JSON datasets, and manage **dotgit** repositories for distribution.

## Build & Test

```sh
go build ./cmd/vuls-data-update
go test ./...
```

## Architecture

- Cobra command tree: root in `pkg/cmd/root/root.go` → `fetch`, `extract`, `dotgit`
- Data-source subcommands are registered in `pkg/cmd/fetch/fetch.go` and `pkg/cmd/extract/extract.go`
- Fetchers live in `pkg/fetch/<domain>/<name>/`, extractors in `pkg/extract/<domain>/<name>/`

## Key Principles

- **Deterministic JSON output is the top priority**: `encoding/json/v2` with `json.Deterministic(true)`, tab indent, always via `util.Write()` — never ad-hoc `json.Marshal`
- Types under `pkg/extract/types/data` are imported by external repos (`filter-vuls-data-extracted-redhat`, `vuls2`) — breaking changes require coordination
- Golden tests: fixtures in `testdata/fixtures/`, expected output in `testdata/golden/`
- Errors are wrapped with `github.com/pkg/errors` — never swallowed, never returned bare without context

## Detailed Guidelines

See `.github/instructions/` for path-scoped conventions:

- `go-code.instructions.md` — Go code conventions
- `golden-test.instructions.md` — test conventions
- `review.instructions.md` — review checklist and severity classification
- `commit-pr.instructions.md` — commit message and PR conventions
- `security.instructions.md` — security guidelines

These mirror `.claude/rules/` (for Claude Code); keep both sides in sync when editing either.
