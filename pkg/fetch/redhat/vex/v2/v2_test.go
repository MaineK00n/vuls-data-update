package v2_test

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/vex/v2"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		deleted  []string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures/",
			// retired by deletions.csv after the archive was taken; the
			// golden tree only covers what Fetch writes, so absence needs
			// its own assertion
			deleted: []string{filepath.Join("2023", "CVE-2023-6237.json")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

				for _, p := range tt.deleted {
					if _, err := os.Stat(filepath.Join(dir, p)); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("Fetch(). %s exists, want deleted", p)
					}
				}
			}
		})
	}
}
