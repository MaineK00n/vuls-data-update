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
		// cut has the body of the first response cut off partway, as by a
		// dropped connection.
		cut      bool
		retry    int
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: []string{"testdata/fixtures/happy/cvrf-cve.tar.bz2"},
		},
		{
			// An XML file in the archive ends partway through.
			name:     "unexpected EOF",
			testdata: []string{"testdata/fixtures/unexpected-eof/cvrf-cve.tar.bz2"},
			hasError: true,
		},
		{
			name:     "unexpected EOF, then whole",
			testdata: []string{"testdata/fixtures/unexpected-eof/cvrf-cve.tar.bz2", "testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			retry:    1,
		},
		{
			// The archive ends partway through an XML file, as it did on
			// 2026-11-18: "read all tar reader: unexpected EOF".
			name:     "truncated archive",
			testdata: []string{"testdata/fixtures/truncated/cvrf-cve.tar.bz2"},
			hasError: true,
		},
		{
			name:     "truncated archive, then whole",
			testdata: []string{"testdata/fixtures/truncated/cvrf-cve.tar.bz2", "testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			retry:    1,
		},
		{
			name:     "body cut off, then whole",
			testdata: []string{"testdata/fixtures/happy/cvrf-cve.tar.bz2"},
			cut:      true,
			retry:    1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(requests.Add(1)) - 1
				p := tt.testdata[min(n, len(tt.testdata)-1)]
				if tt.cut && n == 0 {
					bs, err := os.ReadFile(p)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					// Half of the archive, and then the connection is gone.
					w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
					_, _ = w.Write(bs[:len(bs)/2])
					_ = http.NewResponseController(w).Flush()
					panic(http.ErrAbortHandler)
				}
				http.ServeFile(w, r, p)
			}))

			dir := t.TempDir()
			err := cvrf_cve.Fetch(cvrf_cve.WithHTTPClient(ts.Client()), cvrf_cve.WithDir(dir), cvrf_cve.WithRetry(tt.retry))
			// Each case is either served whole on its last try or fails on
			// every one, so it asks once more than it retries.
			if n := int(requests.Load()); n != tt.retry+1 {
				t.Errorf("requests = %d, want %d", n, tt.retry+1)
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
