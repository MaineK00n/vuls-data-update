package appstreamlifecycle_test

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

	appstreamlifecycle "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/appstream-lifecycle"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/support/policy/updates/rhel-app-streams-life-cycle":
					http.ServeFile(w, r, filepath.Join(tt.testdata, "rhel-app-streams-life-cycle.html"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := appstreamlifecycle.Fetch(appstreamlifecycle.WithBaseURL(fmt.Sprintf("%s/support/policy/updates/rhel-app-streams-life-cycle", ts.URL)), appstreamlifecycle.WithDir(dir), appstreamlifecycle.WithRetry(0))
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

					rel := strings.TrimPrefix(strings.TrimPrefix(path, dir), string(os.PathSeparator))

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					want, err := os.ReadFile(filepath.Join("testdata", "golden", rel))
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
