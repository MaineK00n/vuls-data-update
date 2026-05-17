package archive_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/bulletin/archive"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{name: "happy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/toc.json":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "toc.json"))
				case strings.HasPrefix(r.URL.Path, "/securitybulletins/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s.md", strings.TrimPrefix(r.URL.Path, "/"))))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := archive.Fetch(
				archive.WithBaseURL(ts.URL),
				archive.WithDir(dir),
				archive.WithRetry(0),
			)
			switch {
			case err != nil && !tt.hasError:
				t.Fatal("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					rel, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", tt.name, rel, file))
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
