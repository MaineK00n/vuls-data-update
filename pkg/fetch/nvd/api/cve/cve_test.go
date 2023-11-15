package cve_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		apiKey        string
		fixturePrefix string
		expectedCount int
		hasError      bool
	}{
		{
			name:          "empty",
			fixturePrefix: "empty",
			expectedCount: 0,
		},
		{
			name:          "1 item",
			fixturePrefix: "1_item",
			expectedCount: 1,
		},
		{
			name:          "Precisely single page",
			fixturePrefix: "3_items",
			expectedCount: 3,
		},
		{
			name:          "Multiple pages",
			fixturePrefix: "3_pages",
			expectedCount: 8,
		},
		{
			// The totalResults is 7 initially, but increases to 8 after 2nd page.
			name:          "Total count increase in the middle of command execution",
			fixturePrefix: "increase",
			expectedCount: 8,
		},
		{
			name:          "With API Key",
			apiKey:        "foobar",
			fixturePrefix: "3_pages",
			expectedCount: 8,
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

				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s-%s.json", startIndex, resultsPerPage)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "/rest/json/cves/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cve.Fetch(cve.WithBaseURL(u), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(3), cve.WithWait(0), cve.WithAPIKey(tt.apiKey), cve.WithResultsPerPage(3))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			actualCount := 0
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

				actualCount++
				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}

			if actualCount != tt.expectedCount {
				t.Errorf("unexpected #files, expected: %d, actual: %d", actualCount, tt.expectedCount)

			}
		})
	}
}
