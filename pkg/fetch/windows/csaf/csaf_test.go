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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/csaf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name             string
		testdataRootPath string
		hasError         bool
	}{
		{
			name:             "happy",
			testdataRootPath: "testdata/fixtures/happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, string(os.PathSeparator)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdataRootPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = csaf.Fetch(csaf.WithBaseURL(u), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(2))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				wantDir, wantFile := filepath.Split(strings.TrimPrefix(path, dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantDir, url.QueryEscape(wantFile)))
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
		})
	}
}
