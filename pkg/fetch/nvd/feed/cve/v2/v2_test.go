package v2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
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
				"testdata/fixtures/nvdcve-2.0-2002.json.gz",
				"testdata/fixtures/nvdcve-2.0-2021.json.gz",
				"testdata/fixtures/nvdcve-2.0-modified.json.gz",
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
			err := v2.Fetch(v2.WithBaseURLs(urls), v2.WithDir(dir), v2.WithRetry(0))
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
