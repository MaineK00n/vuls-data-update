package json_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/json"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
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
			name: "include 404 (fails)",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-0000-0000", // per-advisory endpoint returns 404
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
					case "PAN-SA-0000-0000":
						http.NotFound(w, r)
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
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
