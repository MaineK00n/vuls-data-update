package salsa_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdata)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			var m salsa.Mirror
			m.ReleaseMain, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ReleaseSecurity, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian-security")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ReleaseBackport, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveMain, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveSecurity, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian-security")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveBackport, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian-backports")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = salsa.Fetch(salsa.WithDataURL(u), salsa.WithDir(dir), salsa.WithRetry(0), salsa.WithMirror(m))
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
