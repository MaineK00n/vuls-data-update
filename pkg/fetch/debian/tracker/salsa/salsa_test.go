package salsa_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		// drop names, as host and path, a request the server cuts off
		// without an answer.
		drop string
		// truncate names, as host and path, a file of the release mirrors
		// the server answers with only its first half.
		truncate string
		// mirrorNotFound makes every Debian mirror answer 404.
		mirrorNotFound bool
		hasError       bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
		},
		{
			// bookworm has only Sources.xz, so the Sources.gz request comes
			// first. Failing, it fails the fetch rather than passing for a
			// compression the mirror does not have.
			name:     "dropped Sources request",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			drop:     "deb.debian.org/debian/dists/bookworm/main/source/Sources.gz",
			hasError: true,
		},
		{
			// Decompressing a cut-off file stops partway through, which fails
			// the fetch rather than writing the packages read up to there.
			name:     "truncated Sources",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			truncate: "deb.debian.org/debian/dists/bookworm/main/source/Sources.xz",
			hasError: true,
		},
		{
			// A Release answered with anything but 200 is skipped, so without
			// the mirrors the fetch writes the tracker lists and no package.
			name:           "mirrors not found",
			testdata:       "testdata/fixtures/security-tracker-master.tar.gz",
			mirrorNotFound: true,
			hasError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Every source is fetched over https, which the in-memory network
				// serves over TLS, so a request without TLS comes from a plain http URL.
				if r.TLS == nil {
					t.Errorf("unexpected plain http request: http://%s%s", r.Host, r.URL.RequestURI())
					http.Error(w, "Client sent an HTTP request to an HTTPS server.", http.StatusBadRequest)
					return
				}

				// The in-memory network routes every mirror host here, so the
				// fixtures are keyed by the production host and path.
				rel := filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/"))
				target := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
				switch {
				case target == tt.drop:
					panic(http.ErrAbortHandler)
				case target == tt.truncate:
					bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", "release", rel))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(bs[:len(bs)/2]))
				case r.Host == "salsa.debian.org":
					http.ServeFile(w, r, tt.testdata)
				case tt.mirrorNotFound:
					http.NotFound(w, r)
				case r.Host == "archive.debian.org":
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
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
