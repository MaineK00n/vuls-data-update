package v1_test

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

	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v1"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/oval_v1_20230706.tar.gz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				datapath := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if _, err := os.Stat(datapath); err != nil {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdata)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = v1.Fetch(v1.WithDataURL(u), v1.WithDir(dir), v1.WithRetry(0))
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
				dir, d := filepath.Split(filepath.Clean(dir))
				_, v := filepath.Split(filepath.Clean(dir))
				if d != "definitions" {
					dir, pd := filepath.Split(filepath.Clean(dir))
					d = filepath.Join(pd, d)
					_, v = filepath.Split(filepath.Clean(dir))
				}
				want, err := os.ReadFile(filepath.Join("testdata", "golden", v, d, file))
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
