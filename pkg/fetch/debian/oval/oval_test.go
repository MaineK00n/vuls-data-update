package oval_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/oval"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		indexof  string
		hasError bool
	}{
		{
			name:    "happy path",
			indexof: "testdata/fixtures/indexof_valid.html",
		},
		{
			name:     "invalid xml",
			indexof:  "testdata/fixtures/indexof_invalid.html",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/") {
					http.ServeFile(w, r, tt.indexof)
				} else if strings.HasSuffix(r.URL.Path, ".xml.bz2") {
					_, f := path.Split(r.URL.Path)
					http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/%s", f))
				} else {
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := oval.Fetch(oval.WithBaseURL(ts.URL), oval.WithDir(dir), oval.WithRetry(0))
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
