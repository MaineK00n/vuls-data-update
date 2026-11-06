package api_test

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cert-cc/api"
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
		{
			name:     "summary-error",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, ok := strings.CutPrefix(r.URL.Path, "/vuls/api/")
				if !ok {
					http.NotFound(w, r)
					return
				}

				var name string
				switch {
				case strings.HasSuffix(p, "/summary/"):
					name = filepath.Join(strings.TrimSuffix(p, "/summary/"), "summary.json")
				case strings.HasSuffix(p, "/vendors/vuls/"):
					name = filepath.Join(strings.TrimSuffix(p, "/vendors/vuls/"), "vendors-vuls.json")
				case strings.HasSuffix(p, "/vendors/"):
					name = filepath.Join(strings.TrimSuffix(p, "/vendors/"), "vendors.json")
				case strings.HasSuffix(p, "/vuls/"):
					name = filepath.Join(strings.TrimSuffix(p, "/vuls/"), "vuls.json")
				default:
					name = filepath.Join(strings.TrimSuffix(p, "/"), "index.json")
				}

				f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						// The fetcher walks every year up to the current one, so
						// a year without a fixture is answered as an empty one.
						if strings.HasSuffix(p, "/summary/") {
							w.Header().Set("Content-Type", "application/json")
							_, _ = w.Write([]byte(`{"count":0,"notes":[]}`))
							return
						}
						http.NotFound(w, r)
						return
					}
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				defer f.Close()

				fi, err := f.Stat()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.ServeContent(w, r, "", fi.ModTime(), f)
			}))

			dir := t.TempDir()
			err := api.Fetch(api.WithHTTPClient(ts.Client()), api.WithDir(dir), api.WithRetry(0), api.WithConcurrency(2), api.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden", tt.name), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
