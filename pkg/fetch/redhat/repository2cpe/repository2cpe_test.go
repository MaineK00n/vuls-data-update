package repository2cpe_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name                string
		repositoryToCPEPath string
		hasError            bool
	}{
		{
			name:                "happy path",
			repositoryToCPEPath: "testdata/fixtures/repository-to-cpe.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			repositoryToCPEURL, err := url.JoinPath(ts.URL, tt.repositoryToCPEPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = repository2cpe.Fetch(repository2cpe.WithRepositoryToCPEURL(repositoryToCPEURL), repository2cpe.WithDir(dir), repository2cpe.WithRetry(0))
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

				want, err := os.ReadFile(filepath.Join("testdata", "golden", "repository-to-cpe.json"))
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
