package cve_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/cve"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s_%s.json", r.URL.Query().Get("offset"), r.URL.Query().Get("limit"))))
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := cve.Fetch(cve.WithBaseURL(fmt.Sprintf("%s/security/cves.json?limit=%%d&offset=%%d&order=oldest&show_hidden=true", ts.URL)), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(1), cve.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
