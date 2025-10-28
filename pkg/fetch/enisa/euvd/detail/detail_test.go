package detail_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/enisa/euvd/detail"
)

func TestFetch(t *testing.T) {
	type args struct {
		r    io.Reader
		opts []detail.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				r: strings.NewReader("EUVD-2025-0001\nEUVD-2025-0002"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "enisaid":
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s.json", r.URL.Query().Get("id"))))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							w.WriteHeader(http.StatusNoContent)
							return
						}
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					defer f.Close()

					fi, err := f.Stat()
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.ServeContent(w, r, "", fi.ModTime(), f)
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "api", "enisaid")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			opts := append([]detail.Option{detail.WithBaseURL(u), detail.WithDir(dir)}, tt.args.opts...)
			err = detail.Fetch(tt.args.r, opts...)
			switch {
			case err != nil && !tt.wantErr:
				t.Error("unexpected error:", err)
			case err == nil && tt.wantErr:
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
