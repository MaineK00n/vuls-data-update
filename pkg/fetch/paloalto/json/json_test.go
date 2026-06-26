package json_test

import (
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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/json"
)

func TestFetch(t *testing.T) {
	type args struct {
		ids []string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-2025-0007",
				},
			},
		},
		{
			name: "include known 404 (skipped)",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-2016-0011", // known upstream 404 regression
				},
			},
		},
		{
			name: "include unknown 404 (fails)",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-0000-0000", // 404 but not a known regression
				},
			},
			hasError: true,
		},
		{
			name: "include server error (still fails)",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-9999-0500",
				},
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/json/"):
					switch path.Base(r.URL.Path) {
					case "PAN-SA-9999-0500":
						http.Error(w, "internal server error", http.StatusInternalServerError)
					default:
						http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := json.Fetch(tt.args.ids, json.WithDataURL(fmt.Sprintf("%s/json/%%s", ts.URL)), json.WithDir(dir), json.WithRetry(1))
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
