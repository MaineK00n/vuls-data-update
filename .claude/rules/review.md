# Review Guidelines

## Review Focus Areas

### Deterministic Output
- Changes to `pkg/extract/types/` must maintain deterministic JSON output
- Verify `Sort()` and `Compare()` are updated for new/modified types
- Check that `util.Write` is used instead of ad-hoc marshaling

### Backward Compatibility
- Types under `pkg/extract/types/data` are imported by external repos (`filter-vuls-data-extracted-redhat`, `vuls2`)
- Breaking changes to these types require coordination
- Use an explicit breaking-change Conventional Commits format such as `feat!(<scope>): ...` or `chore!(<scope>): ...`

### Correctness and Edge Cases
- Regex patterns: check for overly restrictive quantifiers (e.g., `\d{4}` vs `\d{4,}` for IDs that can have 5+ digits)
- Data source coverage: check for missing variants (e.g., SUSE has both `suse.linux.enterprise.micro` and `suse.linux.micro`)
- Enum completeness: when matching advisory prefixes (RLSA-, RBSA-, etc.), verify all valid prefixes are handled

### Error Handling
- **Errors must not be swallowed.** Flag any `_ = f()` on a fallible call, or dropped errors with no logging/justification.
- **Errors should be wrapped, not returned bare**, unless the caller already has full context. Look for `return err` that loses the current function's context.
- Use `github.com/pkg/errors` consistently (not `fmt.Errorf("...: %w", err)`)
- Error messages: lowercase verb phrase in library code, `"failed to ..."` in `pkg/cmd/`
- Validation errors: use `"unexpected X. expected: %q, actual: %q"` pattern
- Non-fatal errors: `slog.Warn(...)` + skip, don't silently ignore

### Code Idioms
- Pre-allocate slices: `make([]T, 0, len(x))` — not `var s []T` when capacity is known
- Avoid `*[]T` (pointer to slice) — pass by value and return
- Use `strings.Contains` over regex for simple checks
- Use `switch` over `if-else` chains for type dispatching
- Fill default directory in options: `dir: filepath.Join(util.CacheDir(), "extract", "<name>")`
- Add `omitempty` on optional string/slice/map/pointer fields; use `omitzero` on struct and `time.Time` fields
- Sort `maps.Keys()` / `slices.Collect()` results when output is logged, cached, or compared
- Flag **unnecessary sorts**: sorting is justified only when downstream logic requires order or the data is emitted to humans/goldens. Sorting right before feeding into `util.Write` (which calls `Sort()`) or before a single unordered loop is waste.
- **Consistency with surrounding code**: new logic should match existing patterns in sibling packages (other fetchers/extractors in the same domain). Divergence without a clear reason is a review finding.
- Standardize naming: don't mix suffixes (e.g., `Cache` vs `Map` — pick one)
- Use `internal/` package for code that is shared within a module but should not be importable externally

### Golden Test Stability
- If golden diffs appear, verify they are intentional
- Widespread unexpected diffs usually indicate a sorting/determinism issue

### Security
- No hardcoded secrets or credentials
- Validate inputs at system boundaries (CLI args, HTTP responses, file paths)
- Avoid `exec.Command("sh", "-c", userInput)` patterns
- Check for path traversal in file operations

### Test Coverage
- New data sources must include golden tests
- Fetcher tests should use recorded HTTP responses (httptest or fixtures)
- "Please add test data" is a common review request — don't skip tests
- Test code may trade CPU/memory efficiency for brevity and clarity, as long as overall test runtime is not meaningfully impacted. Don't flag readable-but-slightly-wasteful patterns in `_test.go`.

### CI / Data Pipeline Integration
- CI/data pipeline orchestration is handled by the separate `vuls-data-db` repository.
- Keep fetch/extract implementation reviews decoupled from `vuls-data-db` pipeline updates; request pipeline changes only when they are explicitly in scope.

## Severity Classification

- **CRITICAL**: Security vulnerability, data corruption, breaking API change without coordination
- **HIGH**: Logic error, swallowed error, missing error handling, test coverage gap for critical path
- **MEDIUM**: Non-idiomatic code, bare `return err` that drops context, missing edge case handling, overly restrictive regex, missing `omitempty`, inconsistency with sibling packages
- **LOW**: Style nit, naming suggestion, minor optimization, unnecessary sort

## Style Reference

For questions not covered above, the [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md) is a reasonable default. Repo-specific rules in this document take precedence.
