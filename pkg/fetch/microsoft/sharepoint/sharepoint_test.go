package sharepoint_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/sharepoint"
)

// The fixture is the page as served, cut down to the row shapes that decide
// what is read out of it.
//
// A row describes one package or two, and where it describes two, the second is
// a language pack on the Subscription Edition, 2019 and 2016 and SharePoint
// Foundation on 2013 and 2010 -- a different product with its own KBs. The
// packages and their KBs are matched by the <br> between them, so a reader that
// took a cell as one string would be left with "KB 5002894KB 5002896" and
// nothing to say which package either belongs to.
//
// The 2016 rows write the version once per package and the others write it once
// for the row. One 2010 row names a package that shipped nothing that month,
// which Microsoft writes out as "No update for June." rather than leaving the
// cell empty, and several 2010 KBs are written as text with no link at all.
//
// Dates are written both ways, "August 11, 2026" and "April 2023", and one row
// opens with a service pack instead. The page also carries a heading and a table
// outside <main>.
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
			// A page whose tables this cannot find is not a page that has lost
			// them: it keeps SharePoint 2010, out of support since 2021,
			// alongside the current release. So the run fails rather than
			// committing an empty raw/ beside a full origin/.
			name:     "page without tables",
			fixture:  "tableless",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(t, tt.fixture))
			defer ts.Close()

			dir := t.TempDir()
			err := sharepoint.Fetch(
				sharepoint.WithBaseURL(ts.URL),
				sharepoint.WithDir(dir),
				sharepoint.WithRetry(0),
				sharepoint.WithWait(0),
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

// handler serves a fixture tree the way learn.microsoft.com serves the page:
// one document per path, and nothing anywhere else.
func handler(t *testing.T, fixture string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, filepath.Clean(r.URL.Path)+".html"))
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
