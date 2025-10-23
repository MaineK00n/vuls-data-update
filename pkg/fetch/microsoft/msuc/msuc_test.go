package msuc_test

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/msuc"
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
				case "Search.aspx":
					bs, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "Search.aspx", strings.TrimPrefix(string(bs), "q=")))
				case "ScopedViewInline.aspx":
					switch r.URL.Query().Get("updateid") {
					case "00000000-1519-4df8-85c1-d985be7f49c3":
						http.Redirect(w, r, "/Thanks.aspx?id=190", http.StatusFound)
					default:
						http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "ScopedViewInline.aspx", r.URL.Query().Get("updateid")))
					}
				case "Thanks.aspx":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "Thanks.aspx", r.URL.Query().Get("id")))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := msuc.Fetch([]string{"KB5025239"}, msuc.WithMSUCURL(ts.URL), msuc.WithDir(dir), msuc.WithRetry(0))
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
