package csaf_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ox/csaf"
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
				switch {
				case strings.HasPrefix(r.URL.Path, "/appsuite/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "appsuite", path.Base(r.URL.Path)))
				case strings.HasPrefix(r.URL.Path, "/dovecot/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "dovecot", path.Base(r.URL.Path)))
				default:
					http.NotFound(w, r)
				}
			}))
			dir := t.TempDir()
			err := csaf.Fetch(csaf.WithHTTPClient(ts.Client()), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(2))
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
