package vulns_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/variot/vulns"
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

			u, err := url.JoinPath(ts.URL, "api", "vulns")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = vulns.Fetch("token", vulns.WithBaseURL(u), vulns.WithDir(dir), vulns.WithRetry(0), vulns.WithConcurrency(1), vulns.WithWait(0))
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
