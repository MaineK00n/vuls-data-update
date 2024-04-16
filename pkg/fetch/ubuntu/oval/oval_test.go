package oval_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/oval"
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
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				want, err := os.ReadFile(filepath.Join(append([]string{"testdata", "golden"}, strings.Split(strings.TrimPrefix(path, dir), string(os.PathSeparator))...)...))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
