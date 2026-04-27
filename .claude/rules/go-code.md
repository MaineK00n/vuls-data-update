# Go Code Conventions

## Go Version and Modern Idioms

- Check `go.mod` for the required Go version. Write code using modern idioms available at that version — do not use patterns superseded by it.
- Use `go fix ./...` to apply automated modernizations. Key fixers include:
  - `any` over `interface{}`
  - `min`/`max` builtins over if/else
  - Use the `new` builtin function where it fits
  - `slices.Contains` over manual loops
  - `slices.Sort` over `sort.Slice` for basic types
  - `strings.CutPrefix`/`strings.Cut` over `HasPrefix`+`TrimPrefix` / `Index`+slice
  - `strings.SplitSeq`/`strings.FieldsSeq` iterators over `Split`/`Fields` when ranging
  - `fmt.Appendf` over `[]byte(fmt.Sprintf(...))`
  - `t.Context()` over `context.WithCancel` in tests
  - `errgroup.Group.Go(...)` (for variables like `g`/`eg`) over manual errgroup goroutine wiring; for plain `sync.WaitGroup`, use `wg.Add(1)` + `go` + `defer wg.Done()`
- When bumping `go` directive in `go.mod`, run `go fix ./...` and commit the result together.

## Deterministic JSON Output

- Use `encoding/json/v2` with `json.Deterministic(true)` and tab indent
- Always use `util.Write(path, content, doSort)` — never ad-hoc `json.Marshal`
- `util.Write` calls `Sort()` for known types, which recursively normalizes all nested slices
- **No need to pre-sort map keys** when building data structures — deterministic map key ordering comes from `json.Deterministic(true)` during encoding

## Types and Schema

- Extracted JSON schema lives under `pkg/extract/types/**`
- When modifying types:
  - Keep output stable/deterministic
  - Update `Sort()` and `Compare()` where applicable
  - Maintain backward compatibility (used by `filter-vuls-data-extracted-redhat` and `vuls2`)

## Adding a New Data Source

1. Implement the fetcher in `pkg/fetch/<domain>/<name>/`
2. Implement the extractor in `pkg/extract/<domain>/<name>/`
3. Wire `newCmd…()` in both `pkg/cmd/fetch/fetch.go` and `pkg/cmd/extract/extract.go`
4. Follow the existing pattern shown by `newCmdAlmaErrata()` (default output under `util.CacheDir()`, `--dir/-d` flag)

## Error Handling

- **Never swallow errors.** Every returned `error` must be handled — return it (wrapped), log it with context, or explicitly document why it is safe to ignore. Avoid `_ = f()` for fallible calls.
- **Do not return errors directly — wrap them** with context using `github.com/pkg/errors` (not `fmt.Errorf("%w")` or `xerrors`). A bare `return err` is acceptable only when the caller already has full context (e.g., an immediate passthrough inside a tiny helper).
- `errors.Wrap(err, "msg")` / `errors.Wrapf(err, "fmt", args)` for wrapping with context
- `errors.Errorf("fmt", args)` for new errors (validation failures etc.)
- Message conventions:
  - Library/inner code: lowercase verb phrase — `"decode json"`, `"open %s"`, `"read %s"`
  - `pkg/cmd/` (Cobra layer): `"failed to ..."` prefix — `"failed to extract almalinux errata"`
  - Validation: `"unexpected X. expected: %q, actual: %q"` pattern
- Sentinel errors (`errors.New`) are rare; check with `errors.Is()`
  - Use specific sentinel errors (e.g., `ErrNotFoundX`) rather than generic ones when callers need to distinguish error types
- Non-fatal errors: `slog.Warn(...)` + skip (e.g., invalid CPE, unparseable score) — still log, never silently drop

## Slice and Map Idioms

- Pre-allocate slices when capacity is known: `make([]T, 0, len(x))`
- For complex capacity: `make([]T, 0, func() int { cap := 0; for ...; return cap }())`
- Avoid `*[]T` (pointer to slice) for mutation — pass slice directly and return
- Use `strings.Contains` over regex for simple substring checks
- Use `switch` over `if-else` chains for type dispatching
- Sort `maps.Keys()` / `slices.Collect()` results **only when** downstream logic requires ordering, or when the output is emitted to humans/goldens/caches. Do not sort speculatively — avoid needless sorts on data that is about to be re-hashed, looped once, or handed to `Sort()`-aware writers like `util.Write`.

## Options Pattern

- New data sources use functional options: `WithDir(dir string) Option`
- Always fill the default directory in the options struct: `dir: filepath.Join(util.CacheDir(), "extract", "<domain>/<name>")`
- Don't leave default paths empty

## JSON Field Tags

- Use `omitempty` on optional string/slice/map/pointer fields; use `omitzero` on struct and `time.Time` fields
- `encoding/json/v2` handles struct tags differently from v1 — no special handling needed for v2-style tags

## CI / Data Pipeline Integration

- CI/data pipeline orchestration is handled by the separate `vuls-data-db` repository.
- Keep fetch/extract implementation changes decoupled from `vuls-data-db` pipeline updates; make pipeline changes separately when they are explicitly in scope.

## Cleanup Helpers

- Use `util.RemoveAll(dir)` when cleaning output trees — it preserves `README.md` and `.git` directories
- `util.CacheDir()` defaults to `~/.cache/vuls-data-update` (or temp dir fallback)

## Consistency With Surrounding Code

- Before writing new logic, scan sibling packages (e.g., other fetchers/extractors under the same domain) for similar patterns and match them. Uniformity across data sources matters more than local micro-optimization.
- If you find yourself inventing a new shape, ask whether an existing one already fits — mirror the established pattern unless there is a concrete reason to diverge.

## Test Code Pragmatics

- In tests, prefer clarity and brevity over CPU/memory efficiency, **as long as total runtime is not meaningfully impacted**.
  - It's fine to rebuild fixtures per subtest, use `reflect.DeepEqual` / `go-cmp` on large structs, or re-read golden files, when doing so keeps the test short and obvious.
  - Don't introduce caching, sync.Pool, or shared mutable state in tests just to shave microseconds.

## When In Doubt

- Follow the [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md) as a sensible default for questions not covered here (naming, initialization, error wrapping, goroutine hygiene, etc.). Repo-specific rules above still take precedence.
