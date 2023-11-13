package cve_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
	"github.com/google/go-cmp/cmp"

	"path/filepath"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		apiKey        string
		fixturePrefix string
		hasError      bool
	}{
		{
			name:          "empty",
			fixturePrefix: "empty",
		},
		{
			name:          "1 item",
			fixturePrefix: "1_item",
		},
		{
			name:          "Precisely single page",
			fixturePrefix: "3_items",
		},
		{
			name:          "Multiple pages",
			fixturePrefix: "3_pages",
		},
		{
			name:          "With API Key",
			apiKey:        "foobar",
			fixturePrefix: "3_pages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startIndex := "0"
				if value := r.URL.Query().Get("startIndex"); value != "" {
					startIndex = value
				}
				resultsPerPage := "2000"
				if value := r.URL.Query().Get("resultsPerPage"); value != "" {
					resultsPerPage = value
				}

				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", fmt.Sprintf("%s-%s-%s.json", tt.fixturePrefix, startIndex, resultsPerPage)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "/rest/json/cves/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			opts := []cve.Option{
				cve.WithBaseURL(u), cve.WithDir(dir), cve.WithAPIKey(tt.apiKey),
				cve.WithConcurrency(3), cve.WithWait(0), cve.WithRetry(0),
				cve.WithResultsPerPage(3),
			}
			err = cve.Fetch(opts...)
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
				want, err := os.ReadFile(filepath.Join("testdata", "golden", tt.fixturePrefix, filepath.Base(dir), file))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). %s (-expected +got):\n%s", file, diff)
				}

				return nil

			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
