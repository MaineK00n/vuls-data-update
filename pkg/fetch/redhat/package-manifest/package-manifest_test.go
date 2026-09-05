package packagemanifest_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	packageManifest "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/package-manifest"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
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
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
