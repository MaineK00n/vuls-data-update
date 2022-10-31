package oval_test

import (
	"encoding/json"
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
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/suse/oval"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata map[string]string
		hasError bool
	}{
		{
			name: "happy path",
			testdata: map[string]string{
				"opensuse 10.2":                   "testdata/fixtures/opensuse.10.2.xml.gz",
				"opensuse 12.1":                   "testdata/fixtures/opensuse.12.1.xml.gz",
				"opensuse 13.2":                   "testdata/fixtures/opensuse.13.2.xml.gz",
				"opensuse tumbleweed":             "testdata/fixtures/opensuse.tumbleweed.xml.gz",
				"opensuse.leap 15.2":              "testdata/fixtures/opensuse.leap.15.2.xml.gz",
				"suse.linux.enterprise.server 9":  "testdata/fixtures/suse.linux.enterprise.server.9.xml.gz",
				"suse.linux.enterprise.server 10": "testdata/fixtures/suse.linux.enterprise.server.10.xml.gz",
				"suse.linux.enterprise.server 15": "testdata/fixtures/suse.linux.enterprise.server.15.xml.gz",
			},
		},
		{
			name:     "invalid name",
			testdata: map[string]string{"SUSE Linux Enterprise Server 15": "testdata/fixtures/suse.linux.enterprise.server.15.xml.gz"},
			hasError: true,
		},
		{
			name:     "invalid version",
			testdata: map[string]string{"suse.linux.enterprise.server 0": "testdata/fixtures/suse.linux.enterprise.server.15.xml.gz"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var datapath string
				for s, dp := range tt.testdata {
					name, ver, found := strings.Cut(s, " ")
					if !found {
						continue
					}
					if strings.HasSuffix(r.URL.Path, fmt.Sprintf("%s.%s.xml.gz", name, ver)) {
						datapath = dp
						break
					}
				}

				if datapath == "" {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close()

			urls := map[string]string{}
			for code, datapath := range tt.testdata {
				u, err := url.JoinPath(ts.URL, datapath)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				urls[code] = u
			}

			dir := t.TempDir()
			err := oval.Fetch(oval.WithURLs(urls), oval.WithDir(dir), oval.WithRetry(0))
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
				_, osname := filepath.Split(filepath.Clean(dir))
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
