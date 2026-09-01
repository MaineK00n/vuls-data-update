package secdb_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		hasError bool
	}{
		{
			name: "happy path",
			files: map[string]string{
				"/":                     "testdata/fixtures/indexof.html",
				"/v3.2":                 "testdata/fixtures/v3.2/indexof.html",
				"/v3.2/main.json":       "testdata/fixtures/v3.2/main.json",
				"/v3.16":                "testdata/fixtures/v3.16/indexof.html",
				"/v3.16/main.json":      "testdata/fixtures/v3.16/main.json",
				"/v3.16/community.json": "testdata/fixtures/v3.16/community.json",
				"/edge":                 "testdata/fixtures/edge/indexof.html",
				"/edge/main.json":       "testdata/fixtures/edge/main.json",
				"/edge/community.json":  "testdata/fixtures/edge/community.json",
			},
		},
		{
			name: "404 not found",
			files: map[string]string{
				"/": "testdata/fixtures/indexof.html",
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f, ok := tt.files[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, f)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := secdb.Fetch(secdb.WithBaseURL(ts.URL), secdb.WithDir(dir), secdb.WithRetry(0))
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
