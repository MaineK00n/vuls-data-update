package oval_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval"
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
				switch {
				case strings.HasSuffix(r.URL.Path, "/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "indexof.html"))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := oval.Fetch(oval.WithBaseURL(ts.URL), oval.WithDir(dir), oval.WithRetry(0), oval.WithConcurrency(1), oval.WithWait(0))
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
