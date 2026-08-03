package apple_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/apple"
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
				switch {
				case strings.HasPrefix(r.URL.Path, "/en-us/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "en-us", path.Base(r.URL.Path)))
				case r.URL.Path == "/kb/HT201222":
					http.Redirect(w, r, "/en-us/100100", http.StatusFound)
				case strings.HasPrefix(r.URL.Path, "/kb/"):
					if _, err := os.Stat(filepath.Join("testdata", "fixtures", tt.name, "en-us", path.Base(r.URL.Path))); err != nil {
						http.NotFound(w, r)
						return
					}
					http.Redirect(w, r, path.Join("/en-us", path.Base(r.URL.Path)), http.StatusFound)
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := apple.Fetch(apple.WithBaseURL(fmt.Sprintf("%s/en-us/100100", ts.URL)), apple.WithDir(dir), apple.WithRetry(0), apple.WithConcurrency(2), apple.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					rel, err := filepath.Rel(dir, p)
					if err != nil {
						return err
					}

					want, err := os.ReadFile(filepath.Join("testdata", "golden", tt.name, rel))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(p)
					if err != nil {
						return err
					}
					got = bytes.ReplaceAll(got, []byte(ts.URL), []byte("https://support.apple.com"))

					if diff := cmp.Diff(string(want), string(got)); diff != "" {
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
