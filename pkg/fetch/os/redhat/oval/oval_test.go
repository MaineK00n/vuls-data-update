package oval_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat/oval"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name                string
		ovalPath            map[string]oval.OvalURL
		repositoryToCPEPath string
		hasError            bool
	}{
		{
			name: "happy path",
			ovalPath: map[string]oval.OvalURL{
				"5": {
					URLs: []string{"testdata/fixtures/oval/com.redhat.rhsa-RHEL5.xml.bz2"},
				},
				"9": {
					Indexof: "testdata/fixtures/oval/v2/RHEL9/",
				},
			},
			repositoryToCPEPath: "testdata/fixtures/repository-to-cpe.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				datapath := strings.TrimPrefix(r.URL.Path, string(os.PathSeparator))
				if strings.HasSuffix(datapath, string(os.PathSeparator)) {
					datapath = filepath.Join(datapath, "indexof.html")
				}
				if _, err := os.Stat(datapath); err != nil {
					http.NotFound(w, r)
				}
				http.ServeFile(w, r, datapath)
			}))
			defer ts.Close()

			ovalURLs := map[string]oval.OvalURL{}
			for v, ovalURL := range tt.ovalPath {
				if ovalURL.Indexof != "" {
					u, err := url.JoinPath(ts.URL, ovalURL.Indexof)
					if err != nil {
						t.Error("unexpected error:", err)
					}
					ovalURLs[v] = oval.OvalURL{Indexof: u}
					continue
				}
				urls := make([]string, 0, len(ovalURL.URLs))
				for _, p := range ovalURL.URLs {
					u, err := url.JoinPath(ts.URL, p)
					if err != nil {
						t.Error("unexpected error:", err)
					}
					urls = append(urls, u)
				}
				ovalURLs[v] = oval.OvalURL{URLs: urls}
			}

			repositoryToCPEURL, err := url.JoinPath(ts.URL, tt.repositoryToCPEPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = oval.Fetch(oval.WithOvalURLs(ovalURLs), oval.WithRepositoryToCPEURLs(repositoryToCPEURL), oval.WithDir(dir))
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
					cmpopts.SortSlices(func(i, j string) bool {
						return i < j
					}),
					cmpopts.SortSlices(func(i, j oval.Package) bool {
						if i.Name == j.Name {
							if i.Status == j.Status {
								return i.Arch < j.Arch
							}
							return i.Status < j.Status
						}
						return i.Name < j.Name
					}),
					cmpopts.SortSlices(func(i, j oval.CPE) bool {
						return i.CPE < j.CPE
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
