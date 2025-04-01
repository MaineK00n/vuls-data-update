package epss_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		hasError bool
	}{
		{
			name: "happy path",
			args: []string{"2021-04-14", "2021-04-22", "2021-09-01", "2022-02-04", "2023-03-07"},
		},
		{
			name:     "404 not found",
			args:     []string{"2021-04-03"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))))
			}))
			defer ts.Close() //nolint:errcheck

			dir := t.TempDir()
			err := epss.Fetch(tt.args, epss.WithDataURL(fmt.Sprintf("%s/epss_scores-%%s.csv.gz", ts.URL)), epss.WithDir(dir), epss.WithRetry(0), epss.WithConcurrency(1), epss.WithWait(0))
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
