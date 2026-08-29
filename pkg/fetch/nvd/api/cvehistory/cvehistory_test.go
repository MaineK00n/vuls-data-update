package cvehistory_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cvehistory"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		args          []cvehistory.Option
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
			// oldValue and newValue are not always a string
			name:          "detail values in array and object",
			fixturePrefix: "nonstring_values",
			expectedCount: 1,
		},
		{
			name:          "Precisely single page",
			fixturePrefix: "3_items",
			expectedCount: 3,
		},
		{
			// Change events of a CVE are spread over the pages.
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
			args:          []cvehistory.Option{cvehistory.WithAPIKey("foobar")},
			fixturePrefix: "3_pages",
			expectedCount: 8,
		},
		{
			name: "specify start and end change date",
			args: []cvehistory.Option{
				cvehistory.WithChangeStartDate(new(time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC))),
				cvehistory.WithChangeEndDate(new(time.Date(2024, time.October, 1, 0, 0, 0, 0, time.UTC))),
			},
			fixturePrefix: "changedate",
			expectedCount: 3,
		},
		{
			// Both IDs are used as path elements, so a malformed one must not be written
			name:          "malformed cveChangeId",
			fixturePrefix: "invalid_id",
			hasError:      true,
		},
		{
			name: "date range exceeds 120 days",
			args: []cvehistory.Option{
				cvehistory.WithChangeStartDate(new(time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC))),
				cvehistory.WithChangeEndDate(new(time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC))),
			},
			fixturePrefix: "changedate",
			hasError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startIndex := "0"
				if value := r.URL.Query().Get("startIndex"); value != "" {
					startIndex = value
				}
				resultsPerPage := "5000"
				if value := r.URL.Query().Get("resultsPerPage"); value != "" {
					resultsPerPage = value
				}

				switch {
				case r.URL.Query().Has("changeStartDate") && r.URL.Query().Has("changeEndDate"):
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s-%s.json", startIndex, resultsPerPage)))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}
					defer f.Close()

					var base struct {
						ResultsPerPage int    `json:"resultsPerPage"`
						StartIndex     int    `json:"startIndex"`
						TotalResults   int    `json:"totalResults"`
						Format         string `json:"format"`
						Version        string `json:"version"`
						Timestamp      string `json:"timestamp"`
						CVEChanges     []struct {
							Change cvehistory.Change `json:"change"`
						} `json:"cveChanges"`
					}
					if err := json.UnmarshalRead(f, &base); err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					s, err := time.Parse("2006-01-02T15:04:05.000-07:00", strings.ReplaceAll(r.URL.Query().Get("changeStartDate"), "%2B", "+"))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}
					e, err := time.Parse("2006-01-02T15:04:05.000-07:00", strings.ReplaceAll(r.URL.Query().Get("changeEndDate"), "%2B", "+"))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
					}

					var filtered []struct {
						Change cvehistory.Change `json:"change"`
					}
					for _, c := range base.CVEChanges {
						t, err := time.Parse("2006-01-02T15:04:05.000", c.Change.Created)
						if err != nil {
							http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						}

						if (t.Equal(s) || t.After(s)) && (t.Equal(e) || t.Before(e)) {
							filtered = append(filtered, c)
						}
					}

					base.TotalResults = len(filtered)
					end := min(base.StartIndex+base.ResultsPerPage, base.TotalResults)
					base.CVEChanges = filtered[base.StartIndex:end]

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
			dir := t.TempDir()
			err := cvehistory.Fetch(append(tt.args, cvehistory.WithHTTPClient(ts.Client()), cvehistory.WithDir(dir), cvehistory.WithRetry(0), cvehistory.WithConcurrency(3), cvehistory.WithWait(0), cvehistory.WithResultsPerPage(3))...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if tt.hasError {
					return
				}

				if n := utiltest.Diff(t, filepath.Join("testdata", "golden", tt.fixturePrefix), dir); n != tt.expectedCount {
					t.Errorf("unexpected #files, expected: %d, actual: %d", tt.expectedCount, n)
				}
			}
		})
	}
}
