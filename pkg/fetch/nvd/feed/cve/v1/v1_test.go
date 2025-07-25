package v1_test

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

	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v1"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata []string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: []string{"testdata/fixtures/nvdcve-1.1-2021.json.gz", "testdata/fixtures/nvdcve-1.1-modified.json.gz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			urls := make([]string, 0, len(tt.testdata))
			for _, c := range tt.testdata {
				u, err := url.JoinPath(ts.URL, c)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				urls = append(urls, u)
			}

			dir := t.TempDir()
			err := v1.Fetch(v1.WithBaseURLs(urls), v1.WithDir(dir), v1.WithRetry(0))
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
			}
		})
	}
}
