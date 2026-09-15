package v2_test

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/vex/v2"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name string
		// deleted are paths deletions.csv retires after the archive was
		// taken; notRequested are the changes.csv rows at or below the
		// cut-off, which must never be asked for. Neither shows up in a
		// walk driven by what Fetch wrote, so both get their own assertion.
		testdata     string
		deleted      []string
		notRequested []string
		hasError     bool
	}{
		{
			name:         "happy",
			testdata:     "testdata/fixtures/",
			deleted:      []string{filepath.Join("2023", "CVE-2023-6237.json")},
			notRequested: []string{"2023/cve-2023-6228.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var requested []string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requested = append(requested, r.URL.Path)
				mu.Unlock()
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdata)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = v2.Fetch(v2.WithBaseURL(u), v2.WithDir(dir), v2.WithRetry(0), v2.WithConcurrency(1), v2.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", dir, file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}

				// The walk above only visits what Fetch wrote, so a
				// document dropped from the tree would go unnoticed.
				golden := filepath.Join("testdata", "golden")
				if err := filepath.WalkDir(golden, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					rel, err := filepath.Rel(golden, path)
					if err != nil {
						return err
					}

					if _, err := os.Stat(filepath.Join(dir, rel)); errors.Is(err, fs.ErrNotExist) {
						t.Errorf("Fetch(). %s is missing, want kept", rel)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}

				for _, p := range tt.deleted {
					if _, err := os.Stat(filepath.Join(dir, p)); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("Fetch(). %s exists, want deleted", p)
					}
				}

				for _, p := range tt.notRequested {
					if slices.ContainsFunc(requested, func(u string) bool { return strings.HasSuffix(u, p) }) {
						t.Errorf("Fetch(). %s was requested, want left to the archive", p)
					}
				}
			}
		})
	}
}
