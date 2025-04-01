package bulletin_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/bulletin"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata []string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: []string{"testdata/fixtures/BulletinSearch.xlsx", "testdata/fixtures/BulletinSearch2001-2008.xlsx"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close() //nolint:errcheck

			urls := make([]string, 0, len(tt.testdata))
			for _, datapath := range tt.testdata {
				u, err := url.JoinPath(ts.URL, datapath)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				urls = append(urls, u)
			}

			dir := t.TempDir()
			err := bulletin.Fetch(bulletin.WithDataURLs(urls), bulletin.WithDir(dir), bulletin.WithRetry(0))
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

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
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
