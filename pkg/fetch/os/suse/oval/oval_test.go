package oval_test

import (
	"encoding/json"
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
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/suse/oval"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		indexof  string
		hasError bool
	}{
		{
			name:    "happy path",
			indexof: "testdata/fixtures/indexof_valid.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/") {
					http.ServeFile(w, r, tt.indexof)
				} else if strings.HasSuffix(r.URL.Path, ".xml.gz") {
					_, f := path.Split(r.URL.Path)
					http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/%s", f))
				} else {
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := oval.Fetch(oval.WithBaseURL(ts.URL), oval.WithDir(dir), oval.WithRetry(0))
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
				dir, v := filepath.Split(filepath.Clean(dir))
				osname := filepath.Base(dir)
				wantb, err := os.ReadFile(filepath.Join("testdata", "golden", osname, v, file))
				if err != nil {
					return err
				}
				var want oval.Advisory
				if err := json.Unmarshal(wantb, &want); err != nil {
					return err
				}

				gotb, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				var got oval.Advisory
				if err := json.Unmarshal(gotb, &got); err != nil {
					return err
				}

				opts := []cmp.Option{
					cmpopts.SortSlices(func(i, j oval.Package) bool {
						if i.Name == j.Name {
							return i.Arch < j.Arch
						}
						return i.Name < j.Name
					}),
				}
				if diff := cmp.Diff(want, got, opts...); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
