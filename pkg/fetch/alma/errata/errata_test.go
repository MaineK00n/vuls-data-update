package errata_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			version:  "8",
			testdata: "testdata/fixtures/errata.full.json",
		},
		{
			name:     "sad path, yet release version",
			version:  "9",
			testdata: "",
			hasError: true,
		},
		{
			name:     "sad path, invalid json",
			version:  "8",
			testdata: "testdata/fixtures/invalid.json",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.testdata == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.testdata)
			}))
			dir := t.TempDir()
			err := errata.Fetch(errata.WithHTTPClient(ts.Client()), errata.WithVersions([]string{tt.version}), errata.WithDir(dir), errata.WithRetry(0))
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
