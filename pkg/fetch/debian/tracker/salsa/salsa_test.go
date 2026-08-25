package salsa_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The in-memory network routes every mirror host here, so the
				// fixtures are keyed by the production host and path.
				rel := filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/"))
				switch r.Host {
				case "salsa.debian.org":
					http.ServeFile(w, r, tt.testdata)
				case "archive.debian.org":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "archive", rel))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "release", rel))
				}
			}))

			dir := t.TempDir()
			err := salsa.Fetch(salsa.WithHTTPClient(ts.Client()), salsa.WithDir(dir), salsa.WithRetry(0))
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
