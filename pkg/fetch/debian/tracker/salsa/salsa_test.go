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
	"github.com/pkg/errors"

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
				datapath := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if _, err := os.Stat(datapath); err != nil {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close() //nolint:errcheck

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
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				var want []byte
				switch filepath.Base(filepath.Dir(path)) {
				case "DLA", "DSA", "DTSA":
					want, err = os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(filepath.Dir(path)), filepath.Base(path)))
					if err != nil {
						return err
					}
				default:
					d, file := filepath.Split(path)
					d, dd := filepath.Split(filepath.Clean(d))
					switch filepath.Base(d) {
					case "CPE", "CVE":
						want, err = os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(filepath.Clean(d)), dd, file))
						if err != nil {
							return err
						}
					default:
						d, file := filepath.Split(path)
						d, dd := filepath.Split(filepath.Clean(d))
						d, ddd := filepath.Split(filepath.Clean(d))
						d, dddd := filepath.Split(filepath.Clean(d))
						d, ddddd := filepath.Split(filepath.Clean(d))
						switch filepath.Base(d) {
						case "packages":
							want, err = os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(filepath.Clean(d)), ddddd, dddd, ddd, dd, file))
							if err != nil {
								return err
							}
						default:
							return errors.Errorf("%s is not expected file", path)
						}
					}
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
