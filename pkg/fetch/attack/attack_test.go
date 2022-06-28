package attack_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/attack"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata attack.DataURL
		hasError bool
	}{
		{
			name: "happy path",
			testdata: attack.DataURL{
				Enterprise: "testdata/fixtures/enterprise-attack.json",
				ICS:        "testdata/fixtures/ics-attack.json",
				Mobile:     "testdata/fixtures/mobile-attack.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testdata := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if _, err := os.Stat(testdata); err != nil {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, testdata)
			}))
			defer ts.Close()

			var urls attack.DataURL
			u, err := url.JoinPath(ts.URL, tt.testdata.Enterprise)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			urls.Enterprise = u
			u, err = url.JoinPath(ts.URL, tt.testdata.ICS)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			urls.ICS = u
			u, err = url.JoinPath(ts.URL, tt.testdata.Mobile)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			urls.Mobile = u

			dir := t.TempDir()
			err = attack.Fetch(attack.WithDataURL(&urls), attack.WithDir(dir), attack.WithRetry(0))
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
				dir, typedir := filepath.Split(filepath.Clean(dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), typedir, file))
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
