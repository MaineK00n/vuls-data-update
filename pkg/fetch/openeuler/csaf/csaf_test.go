package csaf_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/csaf"
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
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, strings.TrimPrefix(r.URL.Path, "/security/data/csaf/")))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "security/data/csaf/")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = csaf.Fetch(csaf.WithBaseURL(u), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(1), csaf.WithWait(0))
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
