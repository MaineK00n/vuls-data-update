package deployment_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/deployment"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := r.URL.Query().Get("$skip")
				if n == "" {
					n = "0"
				}

				bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s.json", n)))
				if err != nil {
					http.NotFound(w, r)
					return
				}

				if _, err := fmt.Fprintf(w, "%s", bytes.ReplaceAll(bs, []byte("https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US/deployment?$skip="), []byte(fmt.Sprintf("http://%s/sug/v2.0/sugodata/v2.0/en-US/deployment?$skip=", r.Host)))); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "sug/v2.0/sugodata/v2.0/en-US/deployment?$skip=0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = deployment.Fetch(deployment.WithDataURL(u), deployment.WithDir(dir), deployment.WithRetry(0))
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
