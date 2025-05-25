package cve_test

import (
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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/cve"
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
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s_%s.json", r.URL.Query().Get("offset"), r.URL.Query().Get("limit"))))
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := cve.Fetch(cve.WithBaseURL(fmt.Sprintf("%s/security/cves.json?limit=%%d&offset=%%d&order=oldest&show_hidden=true", ts.URL)), cve.WithDir(dir), cve.WithRetry(0), cve.WithConcurrency(1), cve.WithWait(0))
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

				wantDir, wantFile := filepath.Split(strings.TrimPrefix(path, dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantDir, url.QueryEscape(wantFile)))
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
