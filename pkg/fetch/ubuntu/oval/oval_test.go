package oval_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/oval"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type indexof struct {
		urlpath  string
		filepath string
	}
	tests := []struct {
		name     string
		indexof  indexof
		hasError bool
	}{
		{
			name: "happy path",
			indexof: indexof{
				urlpath:  "/oval/",
				filepath: "testdata/fixtures/indexof_valid.html",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.indexof.urlpath {
					http.ServeFile(w, r, tt.indexof.filepath)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
			}))
			dir := t.TempDir()
			err := oval.Fetch(oval.WithHTTPClient(ts.Client()), oval.WithDir(dir), oval.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
