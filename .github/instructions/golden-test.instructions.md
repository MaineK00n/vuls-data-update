---
description: "Test conventions: golden tests (fixtures/golden), inline table-driven tests, cmp.Diff, httptest patterns"
---
# Test Conventions

## Golden Tests (fixture → golden comparison)

### Structure

- Fixtures (input data): `testdata/fixtures/`
- Golden output (expected results): `testdata/golden/`
- Both directories are committed to git

### Test Helpers

Use helpers from `pkg/extract/util/test/test.go`:
- `QueryUnescapeFileTree()` — materializes fixtures with URL-escaped filenames
- `Diff()` — compares output against golden files (`datasource.json`, `data/`, `cpe/`, etc.)

### URL-Escaped Filenames

Golden filenames may be URL-escaped (e.g., `%2F` for `/`). This is intentional for filesystem compatibility. Always use `QueryUnescapeFileTree()` when materializing fixtures.

### When Golden Diffs Appear

If a change causes widespread golden diffs:
1. **Check determinism**: Verify `util.Write` and `types/*/Sort` are correct
2. **Check sorting**: Ensure `Sort()`/`Compare()` are updated for any new or modified types
3. **Update golden files**: If the diff is intentional, run the relevant extractor and copy the output into `testdata/golden/`. This repo does not provide a generic test flag for updating golden files.

### Writing New Golden Tests

Golden tests also use a table-driven (test matrix) pattern with `t.Run`:

```go
tests := []struct {
    name   string
    args   string
    golden string
}{
    {
        name:   "happy",
        args:   "./testdata/fixtures/happy",
        golden: "./testdata/golden/happy",
    },
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        dir := t.TempDir()
        err := pkg.Extract(tt.args, pkg.WithDir(dir))
        // ... error check ...
        ep, _ := filepath.Abs(tt.golden)
        gp, _ := filepath.Abs(dir)
        utiltest.Diff(t, ep, gp)
    })
}
```

- **Single-case**: fixture/golden paths are directly under `testdata/fixtures`, `testdata/golden` (no subdirectories)
- **Multi-case**: each test case explicitly specifies `testdata/fixtures/<name>/`, `testdata/golden/<name>/` in struct fields

### Where Used

`pkg/extract/<domain>/<name>/` (extractors), `pkg/dotgit/` (pull, log, ls, cat, find, grep etc.)

## Inline Unit Tests (table-driven)

### Pattern

Standard Go table-driven tests with subtests. No testify — use stdlib + `github.com/google/go-cmp/cmp`:

```go
func TestFoo(t *testing.T) {
    tests := []struct {
        name string
        args args
        want <type>
    }{
        {name: "case description", args: args{...}, want: ...},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := Foo(tt.args.x)
            if diff := cmp.Diff(tt.want, got); diff != "" {
                t.Errorf("(-expected +got):\n%s", diff)
            }
        })
    }
}
```

### Assertion Methods

- **`cmp.Diff`** (preferred for structs/slices): `if diff := cmp.Diff(want, got); diff != "" { t.Errorf(...) }`
  - Use `cmpopts.SortSlices(...)`, `cmpopts.IgnoreFields(...)`, `cmpopts.EquateApproxTime(...)` as needed
- **Direct `==`/`!=`** (for scalars, int, bool, string): `if got != tt.want { t.Errorf("Foo() = %v, want %v", got, tt.want) }`
- **Error checks**: `if (err != nil) != tt.wantErr { t.Errorf("Foo() error = %v, wantErr %v", err, tt.wantErr) }`

### Common Setup Patterns

- **`t.TempDir()`** for file I/O tests
- **`httptest.NewServer`** for HTTP-dependent tests (fetch packages)
- **`type args struct`** to group function parameters in test table
- **`type fields struct`** to decompose struct-under-test fields

### Where Used

`pkg/extract/types/**` (Sort, Compare, Contains, Accept methods), `pkg/extract/util/`
