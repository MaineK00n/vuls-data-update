package packagemanifest_test

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

	packageManifest "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/package-manifest"
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
				major := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/en/documentation/red_hat_enterprise_linux/"), "/html-single/package_manifest/index")
				http.ServeFile(w, r, filepath.Join(tt.testdata, fmt.Sprintf("%s.html", major)))
			}))
			defer ts.Close()

			dir := t.TempDir()

			err := packageManifest.Fetch(tt.args, packageManifest.WithBaseURL(fmt.Sprintf("%s/en/documentation/red_hat_enterprise_linux/%%s/html-single/package_manifest/index", ts.URL)), packageManifest.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err != nil:
			case tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					rel, err := filepath.Rel(dir, path)
					if err != nil {
						return err
					}

					want, err := os.ReadFile(filepath.Join("testdata", "golden", rel))
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
			}
		})
	}
}
