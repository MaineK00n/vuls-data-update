package msuc_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/windows/msuc"
	"github.com/google/go-cmp/cmp"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "Search.aspx":
					http.ServeFile(w, r, filepath.Join(tt.testdata, "search"))
				case "ScopedViewInline.aspx":
					http.ServeFile(w, r, filepath.Join(tt.testdata, r.URL.Query().Get("updateid")))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := msuc.Fetch([]string{"KB5025239"}, msuc.WithMSUCURL(ts.URL), msuc.WithDir(dir), msuc.WithRetry(0))
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

				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(path)))
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
