package releaseinfo_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/releaseinfo"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
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
		redirect bool
		hasError bool
	}{
		{
			name:    "happy",
			fixture: "happy",
			golden:  "happy",
		},
		{
			// learn.microsoft.com answers some paths with a redirect that appends
			// a ?view=. The page is stored under the name of the URL it was asked
			// for, so the tree is the same as when it answers directly.
			name:     "redirected",
			fixture:  "happy",
			golden:   "happy",
			redirect: true,
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
		{
			// The canonical link is what relative hrefs are resolved against.
			// One that does not parse fails the run rather than leaving them
			// stored unresolved.
			name:     "canonical link that does not parse",
			fixture:  "bad-canonical",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(t, tt.fixture, tt.redirect))
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
			case err != nil && tt.hasError:
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden", tt.golden), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

// handler serves a fixture tree the way learn.microsoft.com serves the pages:
// one document per path, and nothing anywhere else. With redirect, a path
// asked for without a query is first sent on to itself with a ?view= appended.
func handler(t *testing.T, fixture string, redirect bool) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		if redirect && r.URL.RawQuery == "" {
			http.Redirect(w, r, r.URL.Path+"?view=windows-server-2025", http.StatusMovedPermanently)
			return
		}

		bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, filepath.Clean(r.URL.Path)+".html"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bs)
	}
}
