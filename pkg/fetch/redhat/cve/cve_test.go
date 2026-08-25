package cve_test

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/cve"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "cve.json":
					f, err := os.Open(filepath.Join("testdata", "fixtures", "cve.json"))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close()

					var entries []any
					if err := json.UnmarshalRead(f, &entries); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					before, err := time.Parse("2006-01-02", r.URL.Query().Get("before"))
					if err != nil {
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
					after, err := time.Parse("2006-01-02", r.URL.Query().Get("after"))
					if err != nil {
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}

					var filtered []any
					for _, e := range entries {
						t, err := time.Parse("2006-01-02T00:00:00Z", e.(map[string]any)["public_date"].(string))
						if err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						}
						if (t.Equal(after) || t.After(after)) && (t.Equal(before) || t.Before(before)) {
							filtered = append(filtered, e)
						}
					}

					page, err := strconv.Atoi(r.URL.Query().Get("page"))
					if err != nil || page < 0 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}

					per_page, err := strconv.Atoi(r.URL.Query().Get("per_page"))
					if err != nil || page < 0 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}

					start := (page - 1) * per_page
					end := start + per_page
					if start > len(filtered) {
						start, end = 0, 0
					} else if end > len(filtered) {
						end = len(filtered)
					}

					bs, err := json.Marshal(filtered[start:end])
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					http.ServeContent(w, r, "cve.json", time.Now(), bytes.NewReader(bs))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
				}
			}))

			dir := t.TempDir()
			err := cve.Fetch(cve.WithHTTPClient(ts.Client()), cve.WithPerPage(2), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(1), cve.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
