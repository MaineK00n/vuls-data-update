package cwe_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cwe"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		hasError bool
	}{
		{
			name: "happy path",
			file: "testdata/fixtures/cwec_latest.xml.zip",
		},
		{
			name:     "no categories",
			file:     "testdata/fixtures/cwec_latest_no_category.xml.zip",
			hasError: true,
		},
		{
			name:     "404 not found",
			file:     "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.file == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.file)
			}))
			dir := t.TempDir()

			// A file from a previous run: a successful fetch replaces it, a
			// failed one must leave it in place.
			previous := filepath.Join(dir, "category", "0.json")
			if err := os.MkdirAll(filepath.Dir(previous), 0o755); err != nil {
				t.Fatal("unexpected error:", err)
			}
			if err := os.WriteFile(previous, []byte("{}\n"), 0o644); err != nil {
				t.Fatal("unexpected error:", err)
			}

			err := cwe.Fetch(cwe.WithHTTPClient(ts.Client()), cwe.WithDir(dir), cwe.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred; the previous output must survive
				if _, err := os.Stat(previous); err != nil {
					t.Error("previous output was not preserved:", err)
				}
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
