package csaf_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		wantErr  string
		hasError bool
	}{
		{
			// CVE-2026-23490 and CVE-2026-27459 write product ID lists as
			// {"$ref": ...}, and they are written as they are: in the first,
			// product_status.fixed is the list the others refer to, and in the
			// second, it refers to itself.
			name: "happy",
		},
		{
			// Once no document holds a reference, ProductIDs.Ref has to go.
			name:     "stale",
			wantErr:  "remove Ref from ProductIDs",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, strings.TrimPrefix(r.URL.Path, "/security/data/csaf/")))
			}))
			dir := t.TempDir()
			err := csaf.Fetch(csaf.WithHTTPClient(ts.Client()), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(1), csaf.WithWait(0))
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
