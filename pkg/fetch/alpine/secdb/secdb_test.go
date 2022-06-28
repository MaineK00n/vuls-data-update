package secdb_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
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
			}

			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
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
