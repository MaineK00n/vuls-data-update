package security_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openssh/security"
)

// pageFilename is what the page is served and stored as, so a fixture for a
// case lives at testdata/fixtures/<case>/<pageFilename>. A case with no such
// directory is how the 404 is produced.
const pageFilename = "security.html"

// serve stands in for the three hosts a fetch talks to, all out of one case's
// fixture directory: the page and the /txt/ documents it cites, the NVD query
// that says which CVE IDs are OpenSSH's, and the CVE records themselves.
func serve(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dir := filepath.Join("testdata", "fixtures", name)

		// path rather than filepath for the request: a URL path is
		// slash-separated whatever the OS. Clean before matching, so that a
		// request reaching upwards is answered from inside the fixture
		// directory or not at all.
		switch p := path.Clean(r.URL.Path); {
		case p == "/rest/json/cves/2.0":
			// A case that pages serves nvd-<startIndex>.json; one that does not
			// serves the same nvd.json whatever the index.
			if f := filepath.Join(dir, fmt.Sprintf("nvd-%s.json", r.URL.Query().Get("startIndex"))); fileExists(f) {
				http.ServeFile(w, r, f)
				return
			}
			http.ServeFile(w, r, filepath.Join(dir, "nvd.json"))
		case path.Dir(p) == "/api/cve":
			http.ServeFile(w, r, filepath.Join(dir, "mitre", fmt.Sprintf("%s.json", path.Base(p))))
		default:
			http.ServeFile(w, r, filepath.Join(dir, filepath.FromSlash(p)))
		}
	})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			// No fixture directory, so the page is not served at all and
			// ServeFile answers 404.
			name:     "notfound",
			hasError: true,
		},
		{
			// A body carrying the page's shape but almost none of its entries:
			// the truncation a proxy or a partial transfer produces, which
			// would otherwise be stored as upstream deleting its history.
			name:     "truncated",
			hasError: true,
		},
		{
			// A full-looking page that is not this one, as an interstitial
			// served with a 200 would be.
			name:     "not-openssh",
			hasError: true,
		},
		{
			// Truncated to 30 entries, each carrying a nested list: 90 list
			// items in all. Counted naively that clears the floor, which is the
			// miscount the skill warns the conversion against and the one this
			// guard must not make either.
			name:     "nested-truncated",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, serve(tt.name))
			dir := t.TempDir()
			err := security.Fetch(security.WithHTTPClient(ts.Client()), security.WithDir(dir), security.WithRetry(0), security.WithConcurrency(1), security.WithWait(0), security.WithNVDWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case tt.hasError:
				// A rejected body must not reach origin/, or the next
				// conversion would read it as the page.
				if _, err := os.Stat(filepath.Join(dir, "origin", pageFilename)); !os.IsNotExist(err) {
					t.Error("rejected page was stored")
				}
			default:
				want, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, pageFilename))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				got, err := os.ReadFile(filepath.Join(dir, "origin", pageFilename))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				if diff := cmp.Diff(string(want), string(got)); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				// The conversion instructions ship with the data they
				// describe, and are the ones this build embeds.
				wantSkill, err := os.ReadFile(filepath.Join("openssh-security-raw", "SKILL.md"))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				gotSkill, err := os.ReadFile(filepath.Join(dir, ".claude", "skills", "openssh-security-raw", "SKILL.md"))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				if diff := cmp.Diff(string(wantSkill), string(gotSkill)); diff != "" {
					t.Errorf("Fetch() skill. (-expected +got):\n%s", diff)
				}

				// The documents the page cites are stored beside it, because
				// an annotation in raw/ quotes one and has to be checkable
				// against a copy that cannot have changed underneath it.
				for _, name := range []string{"release-1.1", "example.adv"} {
					want, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, "txt", name))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					got, err := os.ReadFile(filepath.Join(dir, "origin", "txt", name))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					if diff := cmp.Diff(string(want), string(got)); diff != "" {
						t.Errorf("Fetch() %s. (-expected +got):\n%s", name, diff)
					}
				}

				// The CVE records the page cannot state itself. OpenSSH is not
				// a CNA, so an entry's ID is only knowable from the CVE List,
				// which makes these the evidence for that one claim.
				for _, id := range []string{"CVE-1999-0001", "CVE-1999-0002"} {
					want, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, "mitre", id+".json"))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					got, err := os.ReadFile(filepath.Join(dir, "origin", "mitre", id+".json"))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					if diff := cmp.Diff(string(want), string(got)); diff != "" {
						t.Errorf("Fetch() %s. (-expected +got):\n%s", id, diff)
					}
				}

				// What must not be stored, and why each is cited in the
				// fixture: a /txt/ document the site no longer serves, which
				// the fetch skips rather than failing over; a link to another
				// host; and two outside /txt/, one of them reaching upwards.
				// CVE-1999-0003 is the same for a record: NVD lists the ID and
				// cve.org does not serve it, which is one record missing rather
				// than a failed run.
				for _, p := range [][]string{
					{"origin", "txt", "gone"},
					{"origin", "txt", "elsewhere"},
					{"origin", "notes", "other"},
					{"origin", "escape"},
					{"origin", "mitre", "CVE-1999-0003.json"},
				} {
					if _, err := os.Stat(filepath.Join(append([]string{dir}, p...)...)); !os.IsNotExist(err) {
						t.Errorf("stored a document outside the cited set: %s", filepath.Join(p...))
					}
				}
			}
		})
	}
}

// TestFetch_pagesCVEIDs pins that the ID list is read to the end rather than
// one page deep.
//
// Both NVD queries answer in one page today -- 134 and 177 against a 2,000
// ceiling -- so this is about what happens when they stop. Reading one page
// would not fail then: it would return a short list, and the advisories whose
// IDs fell off it would simply have no record to be annotated from, with
// nothing to say any were missed.
func TestFetch_pagesCVEIDs(t *testing.T) {
	ts := httptest.NewTestServer(t, serve("paged"))
	dir := t.TempDir()
	if err := security.Fetch(security.WithHTTPClient(ts.Client()), security.WithDir(dir), security.WithRetry(0), security.WithConcurrency(1), security.WithWait(0), security.WithNVDWait(0), security.WithResultsPerPage(2)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	// The third ID is only on the second page.
	for _, id := range []string{"CVE-1999-0001", "CVE-1999-0002", "CVE-1999-0003"} {
		if _, err := os.Stat(filepath.Join(dir, "origin", "mitre", id+".json")); err != nil {
			t.Errorf("record missing, so its page was not read: %s", id)
		}
	}
}

// TestFetch_keepsRaw pins the one way this fetcher differs from every other:
// it replaces origin/ and leaves the rest of the tree alone. raw/ holds records
// converted from the page by hand and no fetch can rebuild them, so wiping the
// output directory -- what util.RemoveAll(dir) does elsewhere -- would discard
// the whole point of the source.
func TestFetch_keepsRaw(t *testing.T) {
	ts := httptest.NewTestServer(t, serve("happy"))
	dir := t.TempDir()

	raw := filepath.Join(dir, "raw", "2025", "OPENSSH-2025-02-18-1.json")
	if err := os.MkdirAll(filepath.Dir(raw), os.ModePerm); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if err := os.WriteFile(raw, []byte(`{"id": "OPENSSH-2025-02-18-1"}`), 0666); err != nil {
		t.Fatal("unexpected error:", err)
	}

	// Two files a previous run left behind that this one does not write: one
	// inside the origin/ it rebuilds, one outside it. Keeping raw/ must not
	// turn into keeping everything that is not raw/, so both have to be gone.
	stale := []string{
		filepath.Join(dir, "origin", "stale.html"),
		filepath.Join(dir, "converted", "stale.json"),
	}
	for _, p := range stale {
		if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
			t.Fatal("unexpected error:", err)
		}
		if err := os.WriteFile(p, []byte("stale"), 0666); err != nil {
			t.Fatal("unexpected error:", err)
		}
	}

	if err := security.Fetch(security.WithHTTPClient(ts.Client()), security.WithDir(dir), security.WithRetry(0), security.WithConcurrency(1), security.WithWait(0), security.WithNVDWait(0)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	got, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if diff := cmp.Diff(`{"id": "OPENSSH-2025-02-18-1"}`, string(got)); diff != "" {
		t.Errorf("Fetch() raw. (-expected +got):\n%s", diff)
	}

	for _, p := range stale {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale file was kept: %s", p)
		}
	}
}
