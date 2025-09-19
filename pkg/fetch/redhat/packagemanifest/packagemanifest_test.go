package packagemanifest_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/packagemanifest"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		args     []string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures",
			args:     []string{"8", "9", "10"},
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

			dir := t.TempDir()

			err := packagemanifest.Fetch(tt.args, packagemanifest.WithBaseURL(fmt.Sprintf("%s/%s/rhel-%%s.html", ts.URL, tt.testdata)), packagemanifest.WithDir(dir))
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

				ss := strings.Split(path, string(os.PathSeparator))
				if len(ss) < 3 {
					return errors.Errorf("invalid path: %s", path)
				}

				wf, err := os.Open(filepath.Join("testdata", "golden", ss[len(ss)-3], ss[len(ss)-2], ss[len(ss)-1]))
				if err != nil {
					return err
				}
				defer wf.Close()

				var want map[string]any
				if err := json.NewDecoder(wf).Decode(&want); err != nil {
					return err
				}

				gf, err := os.Open(path)
				if err != nil {
					return err
				}
				defer gf.Close()

				var got map[string]any
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}

				if diff := cmp.Diff(want, got, cmpopts.IgnoreMapEntries(func(key string, _ any) bool {
					return key == "source"
				})); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
