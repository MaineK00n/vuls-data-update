package cvrf_test

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/cvrf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		updates  string
		hasError bool
	}{
		{
			name:    "happy path",
			updates: "testdata/fixtures/updates",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(path.Clean(r.URL.Path)) {
				case "updates":
					f, err := os.Open(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/"))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					s := strings.ReplaceAll(string(bs), "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf", fmt.Sprintf("http://%s/testdata/fixtures", r.Host))

					http.ServeContent(w, r, "updates", time.Now(), strings.NewReader(s))
				default:
					http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.updates)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cvrf.Fetch(cvrf.WithDataURL(u), cvrf.WithDir(dir), cvrf.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", dir, file))
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
			}
		})
	}
}
