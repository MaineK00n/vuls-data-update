package cvrf_cve_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf_cve"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name string
		// testdata are the archives served, one per request in turn, the last
		// to every request after.
		testdata []string
		// half has the first response send half of its archive. "dropped"
		// drops the connection there, short of the Content-Length it gave.
		// "short" ends the response there, as one of a file that upstream is
		// still writing would.
		half string
		// status, if set, answers every request with it and an empty body.
		status       int
		retry        int
		wantRequests int
		hasError     bool
	}{
		{
			name:         "happy path",
			testdata:     []string{"testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			wantRequests: 1,
		},
		{
			// An XML file in the archive ends partway through.
			name:         "unexpected EOF",
			testdata:     []string{"testdata/fixtures/unexpected-eof/cvrf-cve.tar.bz2"},
			wantRequests: 1,
			hasError:     true,
		},
		{
			name:         "unexpected EOF, then whole",
			testdata:     []string{"testdata/fixtures/unexpected-eof/cvrf-cve.tar.bz2", "testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			retry:        1,
			wantRequests: 2,
		},
		{
			// The archive ends partway through an XML file, as it did on
			// 2026-11-18: "read all tar reader: unexpected EOF".
			name:         "truncated archive",
			testdata:     []string{"testdata/fixtures/truncated/cvrf-cve.tar.bz2"},
			wantRequests: 1,
			hasError:     true,
		},
		{
			name:         "truncated archive, then whole",
			testdata:     []string{"testdata/fixtures/truncated/cvrf-cve.tar.bz2", "testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			retry:        1,
			wantRequests: 2,
		},
		{
			name:         "body cut off, then whole",
			testdata:     []string{"testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			half:         "dropped",
			retry:        1,
			wantRequests: 2,
		},
		{
			name:         "archive cut short, then whole",
			testdata:     []string{"testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			half:         "short",
			retry:        1,
			wantRequests: 2,
		},
		{
			// An empty body would read as an archive that ends partway
			// through, but the status is what failed, and it is not retried.
			name:         "not found",
			status:       http.StatusNotFound,
			retry:        1,
			wantRequests: 1,
			hasError:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(requests.Add(1)) - 1
				if tt.status != 0 {
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(tt.status)
					return
				}
				p := tt.testdata[min(n, len(tt.testdata)-1)]
				if tt.half != "" && n == 0 {
					bs, err := os.ReadFile(p)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					switch tt.half {
					case "dropped":
						w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
						_, _ = w.Write(bs[:len(bs)/2])
						_ = http.NewResponseController(w).Flush()
						panic(http.ErrAbortHandler)
					case "short":
						w.Header().Set("Content-Length", strconv.Itoa(len(bs)/2))
						_, _ = w.Write(bs[:len(bs)/2])
						return
					}
				}
				http.ServeFile(w, r, p)
			}))

			dir := t.TempDir()
			err := cvrf_cve.Fetch(cvrf_cve.WithHTTPClient(ts.Client()), cvrf_cve.WithDir(dir), cvrf_cve.WithRetry(tt.retry))
			if n := int(requests.Load()); n != tt.wantRequests {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
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
