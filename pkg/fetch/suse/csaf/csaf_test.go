package csaf_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		indexof  string
		hasError bool
	}{
		{
			name:    "happy path",
			indexof: "testdata/fixtures/indexof.html",
		},
		{
			name:     "404 not found",
			indexof:  "testdata/fixtures/invalid_href.html",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.ServeFile(w, r, tt.indexof)
					return
				}
				_, f := path.Split(r.URL.Path)
				f = filepath.Join(filepath.Dir(tt.indexof), f)
				if _, err := os.Stat(f); err != nil {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, f)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := csaf.Fetch(csaf.WithBaseURL(ts.URL), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(2), csaf.WithWait(1))
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
