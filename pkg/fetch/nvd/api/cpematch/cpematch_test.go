package cpematch_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cpematch"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name          string
		args          []cpematch.Option
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
			// The totalResults is 7 initially, but increases to 8 after 2nd page.
			name:          "Total count increase in the middle of command execution",
			fixturePrefix: "increase",
		},
		{
			name:          "With API Key",
			args:          []cpematch.Option{cpematch.WithAPIKey("foobar")},
			fixturePrefix: "3_pages",
		},
		{
			name: "specify start and end mod date",
			args: []cpematch.Option{
				cpematch.WithLastModStartDate(new(time.Date(2023, time.November, 15, 23, 0, 0, 0, time.UTC))),
				cpematch.WithLastModEndDate(new(time.Date(2023, time.November, 15, 23, 30, 0, 0, time.UTC))),
			},
			fixturePrefix: "moddate",
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
						ResultsPerPage int    `json:"resultsPerPage"`
						StartIndex     int    `json:"startIndex"`
						TotalResults   int    `json:"totalResults"`
						Format         string `json:"format"`
						Version        string `json:"version"`
						Timestamp      string `json:"timestamp"`
						MatchData      []struct {
							MatchCriteria cpematch.MatchCriteria `json:"matchString"`
						} `json:"matchStrings"`
					}
					if err := json.UnmarshalRead(f, &base); err != nil {
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
						MatchCriteria cpematch.MatchCriteria `json:"matchString"`
					}
					for _, d := range base.MatchData {
						t, err := time.Parse("2006-01-02T15:04:05.000", d.MatchCriteria.LastModified)
						if err != nil {
							http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						}

						if (t.Equal(s) || t.After(s)) && (t.Equal(e) || t.Before(e)) {
							filtered = append(filtered, d)
						}
					}

					base.TotalResults = len(filtered)
					end := min(base.StartIndex+base.ResultsPerPage, base.TotalResults)
					base.MatchData = filtered[base.StartIndex:end]

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

			u, err := url.JoinPath(ts.URL, "/rest/json/cpematch/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cpematch.Fetch(append(tt.args, cpematch.WithBaseURL(u), cpematch.WithDir(dir), cpematch.WithRetry(0), cpematch.WithConcurrency(3), cpematch.WithWait(0), cpematch.WithResultsPerPage(3))...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden", tt.fixturePrefix), dir)

			}
		})
	}
}
