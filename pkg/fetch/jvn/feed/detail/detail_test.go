package detail_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/detail"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "www.jpcert.or.jp" {
					// Real JPCERT-AT alert page saved under testdata/fixtures.
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", strings.TrimPrefix(r.URL.Path, "/")))
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
			}))
			dir := t.TempDir()
			err := detail.Fetch(detail.WithHTTPClient(ts.Client()), detail.WithDir(dir), detail.WithRetry(0))
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
