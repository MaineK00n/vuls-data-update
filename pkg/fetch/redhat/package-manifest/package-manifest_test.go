package packagemanifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	packageManifest "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/package-manifest"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		dir      string // the tree the run starts in, as the last run left it
		origin   string // the pages origin/ starts with, copied into dir
		saved    string // a directory of saved pages, every one given to the run
		golden   string
		wantErr  string
		hasError bool
	}{
		{
			// The saved pages are stored in origin/, cut down to their
			// <article>, and the tables are read from them. RHEL 8 and 9
			// publish the manifest as one page, built with DocBook, where a
			// table is named by the anchor of its title. RHEL 10 publishes a
			// page for each repository, built with DITA-OT, where it is named
			// by the ids of its header cells.
			name:   "happy",
			saved:  filepath.Join("testdata", "fixtures", "happy"),
			golden: filepath.Join("testdata", "golden", "happy"),
		},
		{
			// A run given no page reads the pages origin/ kept, as the job in
			// vuls-data-db does on the pages restored there, and rebuilds the
			// rest of the tree: a table no page holds any more goes, and the
			// README is written again.
			name:   "reread",
			dir:    filepath.Join("testdata", "fixtures", "reread"),
			origin: filepath.Join("testdata", "golden", "happy", "origin"),
			golden: filepath.Join("testdata", "golden", "happy"),
		},
		{
			// A saved page may write the anchors of RHEL 9's titles out as
			// URLs, and the tables are named by their fragments all the same.
			name:   "anchor-url",
			saved:  filepath.Join("testdata", "fixtures", "anchor-url"),
			golden: filepath.Join("testdata", "golden", "anchor-url"),
		},
		{
			// No page has been stored yet.
			name:     "no-origin",
			wantErr:  "find pages in",
			hasError: true,
		},
		{
			// What the URL of RHEL 10's single page now redirects to: the top
			// of the RHEL 10 documentation, which has no canonical link.
			name:     "saved-landing",
			saved:    filepath.Join("testdata", "fixtures", "saved-landing"),
			wantErr:  "unexpected number of canonical links",
			hasError: true,
		},
		{
			// A canonical link whose path climbs out of the documentation
			// would store the page outside origin/.
			name:     "saved-path",
			saved:    filepath.Join("testdata", "fixtures", "saved-path"),
			wantErr:  "unexpected canonical link",
			hasError: true,
		},
		{
			name:     "saved-no-article",
			saved:    filepath.Join("testdata", "fixtures", "saved-no-article"),
			wantErr:  "unexpected article element",
			hasError: true,
		},
		{
			name:     "saved-two-articles",
			saved:    filepath.Join("testdata", "fixtures", "saved-two-articles"),
			wantErr:  "unexpected article element",
			hasError: true,
		},
		{
			// The page that introduces RHEL 10's repository pages holds no
			// table of its own.
			name:     "saved-no-table",
			saved:    filepath.Join("testdata", "fixtures", "saved-no-table"),
			wantErr:  "no table found in the article",
			hasError: true,
		},
		{
			// RHEL 10's BaseOS page, saved twice: one would be stored over
			// the other.
			name:     "saved-twice",
			saved:    filepath.Join("testdata", "fixtures", "saved-twice"),
			wantErr:  "duplicate page",
			hasError: true,
		},
		{
			// cut refuses such a page, but origin/ can be changed by hand.
			name:     "no-table",
			dir:      filepath.Join("testdata", "fixtures", "no-table"),
			wantErr:  "page: 10/plan-repositories.html: no table found",
			hasError: true,
		},
		{
			// RHEL 9's manifest moved to a page for each repository, with its
			// single page kept: both hold the table of BaseOS.
			name:     "duplicate",
			dir:      filepath.Join("testdata", "fixtures", "duplicate"),
			wantErr:  "duplicate table",
			hasError: true,
		},
		{
			// RHEL 10's BaseOS page, put beside the directories of the
			// releases rather than in 10/, would not be read.
			name:     "misplaced",
			dir:      filepath.Join("testdata", "fixtures", "misplaced"),
			wantErr:  "expected: a directory for a major release",
			hasError: true,
		},
		{
			// RHEL 10's BaseOS page, stored as .htm, would not be read.
			name:     "not-html",
			dir:      filepath.Join("testdata", "fixtures", "not-html"),
			wantErr:  "expected: a page, as a .html file",
			hasError: true,
		},
		{
			// A reference names a file in the directory of its release, and
			// one with a path in it would name another.
			name:     "reference-path",
			dir:      filepath.Join("testdata", "fixtures", "reference-path"),
			wantErr:  "unexpected reference",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.dir != "" {
				if err := os.CopyFS(dir, os.DirFS(tt.dir)); err != nil {
					t.Fatalf("copy %s: %v", tt.dir, err)
				}
			}
			if tt.origin != "" {
				if err := os.CopyFS(filepath.Join(dir, "origin"), os.DirFS(tt.origin)); err != nil {
					t.Fatalf("copy %s: %v", tt.origin, err)
				}
			}
			var saved []string
			if tt.saved != "" {
				ms, err := filepath.Glob(filepath.Join(tt.saved, "*.html"))
				if err != nil {
					t.Fatalf("glob %s: %v", tt.saved, err)
				}
				saved = ms
			}

			err := packageManifest.Fetch(saved, packageManifest.WithDir(dir))
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
			}
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(tt.golden, dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

// TestFetch_failedRun checks that a run that fails on a page given leaves the
// tree as it was, the pages origin/ kept included.
func TestFetch_failedRun(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
	}{
		{
			// A page that cut takes, with a table the fetch does not know.
			name:    "bad-header",
			wantErr: "unexpected first header",
		},
		{
			// A page under a new name that holds a table a page kept holds.
			name:    "duplicate",
			wantErr: "duplicate table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			golden := filepath.Join("testdata", "golden", "happy")
			dir := t.TempDir()
			if err := os.CopyFS(dir, os.DirFS(golden)); err != nil {
				t.Fatalf("copy %s: %v", golden, err)
			}
			saved, err := filepath.Glob(filepath.Join("testdata", "fixtures", "failed-run", tt.name, "*.html"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}

			err = packageManifest.Fetch(saved, packageManifest.WithDir(dir))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
			}
			if err := utiltest.Diff(golden, dir); err != nil {
				t.Error("unexpected error:", err)
			}
		})
	}
}
