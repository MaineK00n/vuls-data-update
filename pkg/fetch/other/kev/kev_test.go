package kev_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/kev"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		hasError bool
	}{
		{
			name: "happy path",
			file: "testdata/fixtures/known_exploited_vulnerabilities.json",
		},
		{
			name:     "404 not found",
			file:     "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.file == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.file)
			}))
			defer ts.Close()

			dataURL, err := url.JoinPath(ts.URL, tt.file)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			dir := t.TempDir()
			err = kev.Fetch(kev.WithDataURL(dataURL), kev.WithDir(dir), kev.WithRetry(0))
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
