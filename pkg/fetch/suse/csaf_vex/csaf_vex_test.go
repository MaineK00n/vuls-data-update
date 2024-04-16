package csaf_vex_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf_vex"
)

func TestFetch(t *testing.T) {
	type args struct {
		years   []string
		indexof string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy path",
			args: args{
				years:   []string{"1999", "2023"},
				indexof: "testdata/fixtures/indexof.html",
			},
		},
		{
			name: "404 not found",
			args: args{
				years:   []string{"0000"},
				indexof: "testdata/fixtures/invalid_href.html",
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.ServeFile(w, r, tt.args.indexof)
					return
				}
				_, f := path.Split(r.URL.Path)
				f = filepath.Join(filepath.Dir(tt.args.indexof), f)
				if _, err := os.Stat(f); err != nil {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, f)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := csaf_vex.Fetch(tt.args.years, csaf_vex.WithBaseURL(ts.URL), csaf_vex.WithDir(dir), csaf_vex.WithRetry(0), csaf_vex.WithConcurrency(2), csaf_vex.WithWait(1))
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

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
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
