package cvrf_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/cvrf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		hasError bool
	}{
		{
			name: "happy path",
			args: []string{"FG-IR-13-008", "FG-IR-23-392"},
		},
		{
			name:     "404 not found",
			args:     []string{"FG-IR-12-001"},
			hasError: true,
		},
		{
			name:     "text/html",
			args:     []string{"FG-IR-24-259"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "FG-IR-24-259":
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write([]byte("<html><body>Too Many Requests</body></html>")); err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", fmt.Sprintf("%s.xml", strings.TrimPrefix(r.URL.Path, string(os.PathSeparator)))))
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := cvrf.Fetch(tt.args, cvrf.WithDataURL(fmt.Sprintf("%s/%%s", ts.URL)), cvrf.WithDir(dir), cvrf.WithRetry(0), cvrf.WithConcurrency(1), cvrf.WithWait(0))
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
