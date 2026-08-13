package releaseinfo_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/releaseinfo"
)

// The fixtures are the pages as served, cut down to the tables that decide what
// is read out of them.
//
// windows-10 carries a lifecycle table, which names no KB article column and
// puts its link on a "Latest update for ESU" cell instead, so a reader keying
// on "a table with a link in it" would take it for a history. Its 1709 table
// holds a <strong> inside a cell, which is visited after its own table's start
// tag and would be read as the 1507 table's label. Both pages also carry a
// <strong> and a table outside <main>.
//
// The 1507 table is one month written out in full -- A, B, OOB, C and D, then
// the B of the month after -- which is the whole of what a build line has to be
// split into, and 1709 is January 2018, where the security release shipped on
// the 3rd rather than on a second Tuesday.
//
// windows-11 and windows-server both carry a 26100 line, being Windows 11 24H2
// and Windows Server 2025, each with its own KBs at its own revisions. Their
// hotpatch calendars share a build number in the same way.
//
// One hotpatch row carries a cell more than the header names and another an
// asterisk after its cadence letter, both as Microsoft has served them. Two
// rows name no KB at all: a month a calendar has reached and Microsoft has not
// shipped, and the Windows Server 2025 RTM row, which is the release rather
// than an update to it.
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
			// them: Microsoft has kept every Windows 10 release back to 1507
			// through its end of support and past it. It is this parser having
			// lost them, and it loses them for every page at once, so the run
			// fails rather than committing an empty raw/ beside a full origin/.
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
			err := releaseinfo.Fetch(
				releaseinfo.WithBaseURL(ts.URL),
				releaseinfo.WithDir(dir),
				releaseinfo.WithRetry(0),
				releaseinfo.WithConcurrency(1),
				releaseinfo.WithWait(0),
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

// handler serves a fixture tree the way learn.microsoft.com serves the pages:
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
