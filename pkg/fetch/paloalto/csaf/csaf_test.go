package csaf_test

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type args struct {
		ids []string
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		hasError bool
	}{
		{
			name:   "happy",
			golden: "happy",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-2025-0007",
				},
			},
		},
		{
			name:   "include non-existent",
			golden: "include-non-existent",
			args: args{
				ids: []string{
					"CVE-2025-0114",
					"PAN-SA-0000-0000",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/csaf/"):
					f, err := os.Open(filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							http.Error(w, `{"error": "Failed to generate CSAF"}`, http.StatusInternalServerError)
							return
						}
						http.Error(w, "internal server error", http.StatusInternalServerError)
						return
					}
					defer f.Close()

					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
				default:
					http.NotFound(w, r)
				}
			}))
			dir := t.TempDir()
			err := csaf.Fetch(tt.args.ids, csaf.WithHTTPClient(ts.Client()), csaf.WithDir(dir), csaf.WithRetry(1))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden", tt.golden), dir)
			}
		})
	}
}
