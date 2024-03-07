package cve_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		args          []cve.Option
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
			args:          []cve.Option{cve.WithAPIKey("foobar")},
			fixturePrefix: "3_pages",
			expectedCount: 8,
		},
		{
			name: "specify start and end mod date",
			args: []cve.Option{
				cve.WithLastModStartDate(func() *time.Time { t := time.Date(2023, time.November, 10, 04, 0, 0, 0, time.UTC); return &t }()),
				cve.WithLastModEndDate(func() *time.Time { t := time.Date(2023, time.November, 10, 07, 0, 0, 0, time.UTC); return &t }()),
			},
			fixturePrefix: "moddate",
			expectedCount: 3,
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

				switch {
				case r.URL.Query().Has("lastModStartDate") && r.URL.Query().Has("lastModEndDate"):
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s-%s.json", startIndex, resultsPerPage)))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}
					defer f.Close()

					var base struct {
						ResultsPerPage  int    `json:"resultsPerPage"`
						StartIndex      int    `json:"startIndex"`
						TotalResults    int    `json:"totalResults"`
						Format          string `json:"format"`
						Version         string `json:"version"`
						Timestamp       string `json:"timestamp"`
						Vulnerabilities []struct {
							CVE cve.CVE `json:"cve"`
						} `json:"vulnerabilities"`
					}
					if err := json.NewDecoder(f).Decode(&base); err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					s, err := time.Parse("2006-01-02T15:04:05.000-07:00", strings.ReplaceAll(r.URL.Query().Get("lastModStartDate"), "%2B", "+"))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}
					e, err := time.Parse("2006-01-02T15:04:05.000-07:00", strings.ReplaceAll(r.URL.Query().Get("lastModEndDate"), "%2B", "+"))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					var filtered []struct {
						CVE cve.CVE `json:"cve"`
					}
					for _, v := range base.Vulnerabilities {
						t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.LastModified)
						if err != nil {
							http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						}

						if (t.Equal(s) || t.After(s)) && (t.Equal(e) || t.Before(e)) {
							filtered = append(filtered, v)
						}
					}

					base.TotalResults = len(filtered)
					end := base.StartIndex + base.ResultsPerPage
					if end > base.TotalResults {
						end = base.TotalResults
					}
					base.Vulnerabilities = filtered[base.StartIndex:end]

					bs, err := json.Marshal(base)
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					i, err := f.Stat()
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					http.ServeContent(w, r, filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s-%s.json", startIndex, resultsPerPage)), i.ModTime(), bytes.NewReader(bs))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s-%s.json", startIndex, resultsPerPage)))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "/rest/json/cves/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cve.Fetch(append(tt.args, cve.WithBaseURL(u), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(3), cve.WithWait(0), cve.WithResultsPerPage(3))...)
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
