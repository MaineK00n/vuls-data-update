package csaf_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

func TestFetch(t *testing.T) {
	type args struct {
		args []string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
		},
		{
			name: "cvrf-only",
			args: args{
				args: []string{"FG-IR-24-437"},
			},
			hasError: true,
		},
		{
			name: "invalid-csaf",
			args: args{
				args: []string{"FG-IR-25-771"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/psirt/"):
					bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, path.Base(r.URL.Path), time.Now(), bytes.NewReader(bytes.ReplaceAll(bs, []byte("?csaf_url=https://filestore.fortinet.com"), []byte(fmt.Sprintf("?csaf_url=http://%s", r.Host)))))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := csaf.Fetch(tt.args.args, csaf.WithBaseURL(fmt.Sprintf("%s/psirt/%%s", ts.URL)), csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(2))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", dir, file))
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
