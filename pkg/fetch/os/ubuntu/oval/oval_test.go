package oval_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/oval"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata map[string]string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: map[string]string{"jammy": "testdata/fixtures/com.ubuntu.jammy.cve.oval.xml.bz2"},
		},
		{
			name:     "invalid xml",
			testdata: map[string]string{"jammy": "testdata/fixtures/invalid.xml.bz2"},
			hasError: true,
		},
		{
			name:     "not found",
			testdata: map[string]string{"jammy": ""},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// com.ubuntu.%s.cve.oval.xml.bz2
				_, f := filepath.Split(r.URL.Path)
				datapath, ok := tt.testdata[strings.TrimSuffix(strings.TrimPrefix(f, "com.ubuntu."), ".cve.oval.xml.bz2")]
				if !ok || datapath == "" {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close()

			urls := map[string]string{}
			for code, datapath := range tt.testdata {
				u, err := url.JoinPath(ts.URL, datapath)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				urls[code] = u
			}

			dir := t.TempDir()
			err := oval.Fetch(oval.WithURLs(urls), oval.WithDir(dir), oval.WithRetry(0))
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
				_, v := filepath.Split(filepath.Clean(dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", v, file))
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
