package csaf_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rel, ok := strings.CutPrefix(r.URL.Path, "/data/csaf/v2/advisories/")
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join(tt.testdata, rel))
			}))

			dir := t.TempDir()
			err := csaf.Fetch(csaf.WithHTTPClient(ts.Client()), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(1), csaf.WithWait(0))
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
