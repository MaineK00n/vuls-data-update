package echo_test

import (
	"encoding/json/v2"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/echo"
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
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "data.json")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = echo.Fetch(echo.WithDataURL(u), echo.WithDir(dir), echo.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				fn := func(path string) (echo.Vulnerability, error) {
					f, err := os.Open(path)
					if err != nil {
						return echo.Vulnerability{}, err
					}
					defer f.Close()

					var v echo.Vulnerability
					if err := json.UnmarshalRead(f, &v); err != nil {
						return echo.Vulnerability{}, err
					}
					return v, nil
				}

				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := fn(filepath.Join("testdata", "golden", dir, file))
					if err != nil {
						return err
					}

					got, err := fn(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(a, b echo.Package) bool { return a.Name < b.Name })); diff != "" {
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
