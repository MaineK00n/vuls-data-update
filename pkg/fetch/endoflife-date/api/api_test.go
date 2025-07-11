package api_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/endoflife-date/api"
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
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
		}))
		defer ts.Close()

		u, err := url.JoinPath(ts.URL, "api/v1/products/full")
		if err != nil {
			t.Error("unexpected error:", err)
		}

		dir := t.TempDir()
		err = api.Fetch(api.WithBaseURL(u), api.WithDir(dir), api.WithRetry(0), api.WithConcurrency(1), api.WithWait(0))
		switch {
		case err != nil && !tt.hasError:
			t.Error("unexpected error:", err)
		case err == nil && tt.hasError:
			t.Error("expected error has not occurred")
		default:
			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				wantDir, wantFile := filepath.Split(strings.TrimPrefix(path, dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantDir, url.QueryEscape(wantFile)))
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
		}
	}
}
