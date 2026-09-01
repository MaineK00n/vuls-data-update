package v1_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v1"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata []string
		hasError bool
	}{
		{
			name: "happy path",
			testdata: []string{
				"testdata/fixtures/nvdcve-1.1-2002.json.gz",
				"testdata/fixtures/nvdcve-1.1-2021.json.gz",
				"testdata/fixtures/nvdcve-1.1-modified.json.gz",
			},
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
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
