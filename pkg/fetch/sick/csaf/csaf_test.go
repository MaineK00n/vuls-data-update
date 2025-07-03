package csaf_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/sick/csaf"
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
				switch path.Base(r.URL.Path) {
				case "csaf-feed-tlp-white.json":
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					s := strings.ReplaceAll(string(bs), "https://www.sick.com", fmt.Sprintf("http://%s", r.Host))

					http.ServeContent(w, r, "ssa-feed-tlp-white.json", time.Now(), strings.NewReader(s))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, ".well-known/csaf/white/csaf-feed-tlp-white.json")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = csaf.Fetch(csaf.WithDataURL(u), csaf.WithDir(dir), csaf.WithRetry(1))
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

					wantDir, wantFile := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", wantDir, url.QueryEscape(wantFile)))
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
