package nvd_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/nvd"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		files    nvd.FeedURL
		hasError bool
	}{
		{
			name: "happy path",
			files: nvd.FeedURL{
				CVE:           []string{"testdata/fixtures/nvdcve-1.1-2021.json.gz", "testdata/fixtures/nvdcve-1.1-modified.json.gz"},
				CPEMatch:      "testdata/fixtures/nvdcpematch-1.0.json.gz",
				CPEDictionary: "testdata/fixtures/official-cpe-dictionary_v2.3.xml.gz",
			},
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

			var urls nvd.FeedURL
			for _, c := range tt.files.CVE {
				u, err := url.JoinPath(ts.URL, c)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				urls.CVE = append(urls.CVE, u)
			}
			u, err := url.JoinPath(ts.URL, tt.files.CPEMatch)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			urls.CPEMatch = u
			u, err = url.JoinPath(ts.URL, tt.files.CPEDictionary)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			urls.CPEDictionary = u

			dir := t.TempDir()
			err = nvd.Fetch(nvd.WithFeedURL(&urls), nvd.WithDir(dir), nvd.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				wantdir := filepath.Join("testdata", "golden", filepath.Base(dir), file)
				if file == "cpe-dictionary.json.gz" {
					wantdir = filepath.Join("testdata", "golden", file)
				}
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
