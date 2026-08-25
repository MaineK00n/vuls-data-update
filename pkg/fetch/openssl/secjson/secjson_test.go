package secjson_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openssl/secjson"
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
		{
			name:     "notfound",
			hasError: true,
		},
		{
			name:     "no-statements",
			hasError: true,
		},
		{
			name:     "unexpected",
			hasError: true,
		},
		{
			name:     "invalid-id",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/news/secjson/":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "indexof.html"))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			dir := t.TempDir()
			err := secjson.Fetch(secjson.WithHTTPClient(ts.Client()), secjson.WithDir(dir), secjson.WithRetry(0), secjson.WithConcurrency(1), secjson.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden", tt.name), dir)
			}
		})
	}
}
