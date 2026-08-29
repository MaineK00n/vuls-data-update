package v1_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch/v1"
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
			testdata: "testdata/fixtures/nvdcpematch-1.0.json.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.testdata)
			}))

			dir := t.TempDir()
			err := v1.Fetch(v1.WithHTTPClient(ts.Client()), v1.WithDir(dir), v1.WithRetry(0))
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
