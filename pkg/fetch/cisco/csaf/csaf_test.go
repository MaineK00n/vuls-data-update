package csaf_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/csaf"
)

func TestFetch(t *testing.T) {
	type args struct {
		ids []string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				ids: []string{
					"cisco-sa-ios-xr-verii-bypass-HhPwQRvx",
					"cisco-sa-snmp-dos-sdxnSUcW",
				},
			},
		},
		{
			name: "include non-existent",
			args: args{
				ids: []string{
					"cisco-sa-ios-xr-verii-bypass-HhPwQRvx",
					"cisco-sa-non-existent",
				},
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/security/center/contentjson/CiscoSecurityAdvisory/"):
					bs, _ := os.ReadFile(filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
					http.ServeContent(w, r, path.Base(r.URL.Path), time.Now(), bytes.NewReader(bs))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close() //nolint:errcheck

			dir := t.TempDir()
			err := csaf.Fetch(tt.args.ids, csaf.WithDataURL(fmt.Sprintf("%s/security/center/contentjson/CiscoSecurityAdvisory/%%s/csaf/%%s.json", ts.URL)), csaf.WithDir(dir), csaf.WithRetry(1))
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
