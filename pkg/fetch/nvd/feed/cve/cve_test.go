package cve_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve"
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
				testdata := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if _, err := os.Stat(testdata); err != nil {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, testdata)
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
			err := cve.Fetch(cve.WithBaseURLs(urls), cve.WithDir(dir), cve.WithRetry(0))
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

				dir, file := filepath.Split(path)
				wantdir := filepath.Join("testdata", "golden", filepath.Base(dir), file)
				want, err := os.ReadFile(wantdir)
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
