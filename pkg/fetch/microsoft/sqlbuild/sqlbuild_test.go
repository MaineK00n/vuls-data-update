package sqlbuild_test

import (
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/sqlbuild"
)

// The fixture is the article as authored, cut down to the rows that decide what
// is read out of it.
//
// It opens with a summary table that names no Knowledge Base column, and closes
// with SQL Server 2000, whose table has a column set of its own. Neither is a
// build history and both sit among the ones that are.
//
// One SQL Server 2016 row has lost its leading pipe, as Microsoft has served it.
// The docs pipeline renders it inside the table, so a reader that stopped there
// would end the table early and read the rest of it as a second one, header and
// all -- turning fifteen rows into one table of one and another of thirteen.
//
// Knowledge Base cells are written both ways: as an address for the KB, and as a
// path to a sibling article in the repository, which is not one. Three rows name
// no KB at all, being the product release rather than an update to it, and one
// of those has an empty cell rather than the "NA" the others use.
func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		golden   string
		hasError bool
	}{
		{
			name:    "happy",
			fixture: "happy",
			golden:  "happy",
		},
		{
			// An article whose tables this cannot find is not an article that
			// has lost them: it lists builds back to SQL Server 6.5, released
			// in 1996. It is this parser having lost them, so the run fails
			// rather than committing an empty raw/ beside a full origin/.
			name:     "article without tables",
			fixture:  "tableless",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(t, tt.fixture))
			defer ts.Close()

			dir := t.TempDir()
			err := sqlbuild.Fetch(
				sqlbuild.WithBaseURL(ts.URL),
				sqlbuild.WithDir(dir),
				sqlbuild.WithRetry(0),
				sqlbuild.WithWait(0),
			)
			switch {
			case err != nil && !tt.hasError:
				t.Fatalf("unexpected error. err: %v", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			case err != nil:
				return
			}

			diff(t, filepath.Join("testdata", "golden", tt.golden), dir)
		})
	}
}

// handler serves a fixture tree the way raw.githubusercontent.com serves the
// repository: one document per path, and nothing anywhere else.
func handler(t *testing.T, fixture string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, filepath.Clean(r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bs)
	}
}

// diff compares the produced tree against golden byte for byte. Bytes rather
// than parsed content: origin/ is only worth keeping if it reproduces exactly,
// and raw/ is written deterministically, so any difference at all is a
// regression.
func diff(t *testing.T, golden, got string) {
	t.Helper()

	want := walk(t, golden)
	have := walk(t, got)

	if d := cmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(have))); d != "" {
		t.Errorf("files (-expected +got):\n%s", d)
	}

	for n, w := range want {
		h, ok := have[n]
		if !ok {
			continue
		}
		if d := cmp.Diff(string(w), string(h)); d != "" {
			t.Errorf("%s (-expected +got):\n%s", n, d)
		}
	}
}

func walk(t *testing.T, root string) map[string][]byte {
	t.Helper()

	out := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}

		bs, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		out[filepath.ToSlash(rel)] = bs
		return nil
	}); err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s. err: %v", root, err)
	}

	return out
}
