package cve_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/cve"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		listfile string
		hasError bool
	}{
		{
			name:     "happy",
			listfile: "testdata/fixtures/cve.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "cve.json":
					f, err := os.Open(strings.TrimPrefix(r.URL.Path, "/"))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close() //nolint:errcheck

					var entries []any
					if err := json.NewDecoder(f).Decode(&entries); err != nil {
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
						t, err := time.Parse("2006-01-02T00:00:00Z", e.(map[string]interface{})["public_date"].(string))
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

					s := strings.ReplaceAll(string(bs), "https://access.redhat.com/hydra/rest/securitydata/cve/", fmt.Sprintf("http://%s/testdata/fixtures/", r.Host))

					http.ServeContent(w, r, "cve.json", time.Now(), strings.NewReader(s))
				default:
					testdata := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
					if _, err := os.Stat(testdata); err != nil {
						http.NotFound(w, r)
						return
					}
					http.ServeFile(w, r, testdata)
				}
			}))
			defer ts.Close() //nolint:errcheck

			u, err := url.JoinPath(ts.URL, tt.listfile)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			u = fmt.Sprintf("%s?page=%%d&after=%%s&before=%%s&per_page=2", u)

			dir := t.TempDir()
			err = cve.Fetch(cve.WithDataURL(u), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(1), cve.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
