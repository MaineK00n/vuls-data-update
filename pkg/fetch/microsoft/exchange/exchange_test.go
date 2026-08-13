package exchange_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/exchange"
)

// The fixture is the page as served, cut down to the rows that decide what is
// read out of it.
//
// Two of its column names are broken across lines -- "Build number<br>(short
// format)" -- and a reader that takes a cell's text straight through gets
// "Build number(short format)", which no lookup by name will find.
//
// The KB is the link on the product's name and nothing else on the page carries
// it. Rows that ship as downloads rather than as KB articles link to the
// Download Center instead, and Exchange Server 2003 is listed with a column set
// of its own and no links at all.
//
// KB5000871 is on four rows across three product versions, which is what the
// March 2021 update did: every supported cumulative update level got its own
// patched build of the one fix.
//
// Exchange Server SE and Exchange Server 2019 are both 15.2, so the table a row
// was filed under is the only thing that tells the two products apart.
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
			// them: it keeps Exchange Server 4.0, released in 1996, alongside
			// the current release. So the run fails rather than committing an
			// empty raw/ beside a full origin/.
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
			err := exchange.Fetch(
				exchange.WithBaseURL(ts.URL),
				exchange.WithDir(dir),
				exchange.WithRetry(0),
				exchange.WithWait(0),
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
