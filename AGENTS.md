# Project Guidelines — vuls-data-update

## What This Repo Does

CLI tool to **fetch** raw vulnerability data sources, **extract** them to canonical JSON datasets, and manage **dotgit** repositories for distribution.

## Build & Test

```sh
go build ./cmd/vuls-data-update
go test ./...
```

→ Architecture and conventions: see `.github/instructions/`
