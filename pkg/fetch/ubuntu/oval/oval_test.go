package oval_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
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
				urlpath:  "/testdata/fixtures/",
				filepath: "testdata/fixtures/indexof_valid.html",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, tt.indexof.urlpath):
					http.ServeFile(w, r, tt.indexof.filepath)
				default:
					http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.indexof.urlpath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = oval.Fetch(oval.WithBaseURL(u), oval.WithDir(dir), oval.WithRetry(0))
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
