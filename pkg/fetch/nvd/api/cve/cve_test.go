package cve_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"

	"path/filepath"
	"sort"
	"time"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name         string
		apiKey       string
		totalResults int
		hasError     bool
	}{
		{
			name:         "No item",
			totalResults: 0,
		},
		{
			name:         "Just single item",
			totalResults: 1,
		},
		{
			name:         "Half of single page",
			totalResults: 1000,
		},
		{
			name:         "Precisely single page",
			totalResults: 2000,
		},
		{
			name:         "Single page plus one",
			totalResults: 2001,
		},
		{
			name:         "Two pages",
			totalResults: 2001,
		},
		{
			name:         "Many (more than concurrency)",
			totalResults: 10000,
		},
		{
			name:         "With API Key",
			apiKey:       "foobar",
			totalResults: 8888,
		},
	}

	cveTemplatePath := "testdata/fixtures/cve.json"
	bs, err := os.ReadFile(cveTemplatePath)
	if err != nil {
		t.Error("Read file failed", err)
	}
	var cveItemTemplate cve.Vulnerability
	if err := json.Unmarshal(bs, &cveItemTemplate); err != nil {
		t.Error("Unmarshal failed", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totalResults := tt.totalResults
			allVs := make([]cve.Vulnerability, 0, totalResults)
			// Sequence numbers in IDs, which will be used to verify result
			expectedSeqNums := make([]int, 0, totalResults)
			for seqNum := 0; seqNum < totalResults; seqNum++ {
				cveItem := cveItemTemplate
				y := rand.Intn(20) + 2000
				cveItem.CVE.ID = fmt.Sprintf("CVE-%d-%d", y, seqNum)
				allVs = append(allVs, cveItem)

				expectedSeqNums = append(expectedSeqNums, seqNum)
			}

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startIndex := 0
				if value := r.URL.Query().Get("startIndex"); value != "" {
					if startIndex, err = strconv.Atoi(value); err != nil {
						t.Error("unexpected error:", err)
					}
				}
				requestedResultsPerPage := 2000
				if value := r.URL.Query().Get("resultsPerPage"); value != "" {
					if requestedResultsPerPage, err = strconv.Atoi(value); err != nil {
						t.Error("unexpected error:", err)
					}
				}
				vs := allVs[startIndex:]
				if requestedResultsPerPage < len(vs) {
					vs = vs[:requestedResultsPerPage]
				}

				now := time.Now()
				cveAPI20 := cve.API20{
					ResultsPerPage:  len(vs),
					StartIndex:      startIndex,
					TotalResults:    totalResults,
					Format:          "NVD_CVE",
					Version:         "2.0",
					Timestamp:       now.Format("2006-01-02T15:04:05.000"),
					Vulnerabilities: vs,
				}
				bs, err := json.Marshal(cveAPI20)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				content := bytes.NewReader(bs)
				http.ServeContent(w, r, "cve-api.json", now, content)
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
			}
			err = cve.Fetch(opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			seqNums := make([]int, 0, totalResults)
			var v cve.Vulnerability

			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				bs, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(bs, &v); err != nil {
					t.Error("Unmarshal failed", err)
				}
				tokens := strings.Split(v.CVE.ID, "-")
				if len(tokens) < 3 {
					t.Errorf("unexpected CVE.ID format: %s (%s)", v.CVE.ID, path)
				}
				seqNum, err := strconv.Atoi(tokens[2])
				if err != nil {
					t.Errorf("unexpected CVE.ID format: %s (%s)", v.CVE.ID, path)
				}
				seqNums = append(seqNums, seqNum)

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}

			sort.Ints(seqNums)
			if !reflect.DeepEqual(expectedSeqNums, seqNums) {
				t.Errorf("CVEs are NOT exhausted, expected=%#v, actual=%#v", expectedSeqNums, seqNums)
			}
		})
	}
}
