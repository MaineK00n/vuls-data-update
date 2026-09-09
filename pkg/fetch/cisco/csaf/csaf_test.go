package csaf_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
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
			defer ts.Close()

			dir := t.TempDir()
			err := csaf.Fetch(tt.args.ids, csaf.WithDataURL(fmt.Sprintf("%s/security/center/contentjson/CiscoSecurityAdvisory/%%s/csaf/%%s.json", ts.URL)), csaf.WithDir(dir), csaf.WithRetry(1))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
