package v2_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v2"
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
				// The fixtures mirror the real layout under /data, so the feed's
				// absolute URLs resolve straight back to this server.
				rel, ok := strings.CutPrefix(r.URL.Path, "/data/")
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", rel))
			}))
			dir := t.TempDir()
			err := v2.Fetch(v2.WithHTTPClient(ts.Client()), v2.WithDir(dir), v2.WithRetry(0))
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
