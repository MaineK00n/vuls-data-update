package csaf_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/intel/csaf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		golden   string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/happy.tar.gz",
			golden:   "testdata/golden/happy",
		},
		{
			name:     "no advisory",
			testdata: "testdata/fixtures/no-advisory.tar.gz",
			hasError: true,
		},
		{
			name:     "invalid advisory id",
			testdata: "testdata/fixtures/invalid-id.tar.gz",
			hasError: true,
		},
		{
			name:     "invalid initial release date",
			testdata: "testdata/fixtures/invalid-date.tar.gz",
			hasError: true,
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
			err = csaf.Fetch(csaf.WithDataURL(u), csaf.WithDir(dir), csaf.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if tt.hasError {
					return
				}

				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					want, err := os.ReadFile(filepath.Join(tt.golden, strings.TrimPrefix(path, dir)))
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
			}
		})
	}
}
