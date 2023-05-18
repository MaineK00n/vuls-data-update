package ovalv1_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat/ovalv1"
	"github.com/google/go-cmp/cmp"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		indexof  string
		hasError bool
	}{
		{
			name:    "happy path",
			indexof: "testdata/fixtures/oval/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				datapath := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if strings.HasSuffix(datapath, string(os.PathSeparator)) {
					datapath = filepath.Join(datapath, "indexof.html")
				}
				if _, err := os.Stat(datapath); err != nil {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.indexof)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = ovalv1.Fetch(ovalv1.WithIndexOf(u), ovalv1.WithDir(dir), ovalv1.WithRetry(0))
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
