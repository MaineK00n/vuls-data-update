package api_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/api"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/advisory.json",
		},
		{
			name:     "invalid json",
			testdata: "testdata/fixtures/invalid.json",
			hasError: true,
		},
		{
			name:     "404 not found",
			testdata: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.testdata == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.testdata)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := api.Fetch(api.WithAdvisoryURL(ts.URL), api.WithDir(dir), api.WithRetry(0))
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
				dir, y := filepath.Split(filepath.Clean(dir))
				_, v := filepath.Split(filepath.Clean(dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", v, y, file))
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
