package cpe_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cpe"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		args          []cpe.Option
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
			args:          []cpe.Option{cpe.WithAPIKey("foobar")},
			fixturePrefix: "3_pages",
			expectedCount: 8,
		},
		{
			name: "specify start and end mod date",
			args: []cpe.Option{
				cpe.WithLastModStartDate(func() *time.Time { t := time.Date(2023, time.November, 14, 21, 35, 0, 0, time.UTC); return &t }()),
				cpe.WithLastModEndDate(func() *time.Time { t := time.Date(2023, time.November, 14, 21, 40, 0, 0, time.UTC); return &t }()),
			},
			fixturePrefix: "moddate",
			expectedCount: 1,
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
						StartIndex     int    `json:"startIndex"`
						ResultsPerPage int    `json:"resultsPerPage"`
						TotalResults   int    `json:"totalResults"`
						Format         string `json:"format"`
						Version        string `json:"version"`
						Timestamp      string `json:"timestamp"`
						Products       []struct {
							CPE cpe.CPE `json:"cpe"`
						} `json:"products"`
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
						CPE cpe.CPE `json:"cpe"`
					}
					for _, p := range base.Products {
						t, err := time.Parse("2006-01-02T15:04:05.000", p.CPE.LastModified)
						if err != nil {
							http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						}

						if (t.Equal(s) || t.After(s)) && (t.Equal(e) || t.Before(e)) {
							filtered = append(filtered, p)
						}
					}

					base.TotalResults = len(filtered)
					end := base.StartIndex + base.ResultsPerPage
					if end > base.TotalResults {
						end = base.TotalResults
					}
					base.Products = filtered[base.StartIndex:end]

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

			u, err := url.JoinPath(ts.URL, "/rest/json/cpes/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cpe.Fetch(append(tt.args, cpe.WithBaseURL(u), cpe.WithDir(dir), cpe.WithRetry(0), cpe.WithConcurrency(3), cpe.WithWait(0), cpe.WithResultsPerPage(3))...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				actualCount := 0
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
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
					t.Errorf("unexpected #files, expected: %d, actual: %d", tt.expectedCount, actualCount)
				}
			}
		})
	}
}
