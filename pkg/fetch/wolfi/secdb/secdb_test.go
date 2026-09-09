package secdb_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"testing"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/wolfi/secdb"
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
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "os/security.json")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = secdb.Fetch(secdb.WithDataURL(u), secdb.WithDir(dir), secdb.WithRetry(0))
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
