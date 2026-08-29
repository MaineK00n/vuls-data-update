package msuc_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/msuc"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			dir := t.TempDir()
			err := msuc.Fetch([]string{"KB5025239"}, msuc.WithHTTPClient(ts.Client()), msuc.WithDir(dir), msuc.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
