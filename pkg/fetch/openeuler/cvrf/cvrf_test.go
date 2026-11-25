package cvrf_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/cvrf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		wantErr  string
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			// index.txt names a file of missingFiles, which is answered 404
			// and skipped, and the rest is written as in happy.
			name: "missing-files",
		},
		{
			// The listed file is served now, so the entry has to go.
			name:     "missing-files-stale",
			wantErr:  "https://repo.openeuler.org/security/data/cvrf/2026/cvrf-openEuler-SA-2026-4863.xml is served now; remove it from missingFiles",
			hasError: true,
		},
		{
			// A 404 for a file that is not listed fails the fetch as before.
			name:     "missing-files-unlisted",
			wantErr:  "error response with status code 404",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, strings.TrimPrefix(r.URL.Path, "/security/data/")))
			}))
			dir := t.TempDir()
			err := cvrf.Fetch(cvrf.WithHTTPClient(ts.Client()), cvrf.WithDir(dir), cvrf.WithRetry(0), cvrf.WithConcurrency(1), cvrf.WithWait(0))
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
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
