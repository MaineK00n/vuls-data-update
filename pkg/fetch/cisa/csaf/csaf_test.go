package csaf_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cisa/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		wantErr  string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures/develop.tar.gz",
		},
		{
			// ICSA-26-288-02 names "organization" twice in an acknowledgment,
			// which encoding/json/v2 rejects. Listed in duplicateNames, it is
			// read with duplicate names allowed, keeping the last.
			name:     "duplicate-names",
			testdata: "testdata/fixtures/duplicate-names.tar.gz",
		},
		{
			// Once upstream fixes the file, the entry has to go.
			name:     "duplicate-names-stale",
			testdata: "testdata/fixtures/duplicate-names-stale.tar.gz",
			wantErr:  "remove it from duplicateNames",
			hasError: true,
		},
		{
			// A file not listed is held to the strict decode.
			name:     "duplicate-names-unlisted",
			testdata: "testdata/fixtures/duplicate-names-unlisted.tar.gz",
			wantErr:  "duplicate object member name",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.testdata)
			}))

			dir := t.TempDir()
			err := csaf.Fetch(csaf.WithHTTPClient(ts.Client()), csaf.WithDir(dir), csaf.WithRetry(0))
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
				if err := utiltest.Diff(filepath.Join("testdata", "golden", tt.name), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
