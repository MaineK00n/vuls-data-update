package amazon_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/amazon"
	"github.com/google/go-cmp/cmp"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name        string
		releasemd   string
		repomd      string
		updateinfos map[string]string
		hasError    bool
	}{
		{
			name:      "happy path",
			releasemd: "testdata/fixtures/releasemd_valid.xml",
			repomd:    "testdata/fixtures/repomd_valid.xml",
			updateinfos: map[string]string{
				"1":    "testdata/fixtures/updateinfo_1.xml.gz",
				"2":    "testdata/fixtures/updateinfo_2.xml.gz",
				"2022": "testdata/fixtures/updateinfo_2022.xml.gz",
			},
		},
		{
			name:      "invalid releasemd",
			releasemd: "testdata/fixtures/releasemd_invalid.xml",
			repomd:    "testdata/fixtures/repomd_valid.xml",
			updateinfos: map[string]string{
				"2022": "testdata/fixtures/updateinfo_2022.xml.gz",
			},
			hasError: true,
		},
		{
			name:   "invalid repomd",
			repomd: "testdata/fixtures/repomd_invalid.xml",
			updateinfos: map[string]string{
				"1": "testdata/fixtures/updateinfo_1.xml.gz",
			},
			hasError: true,
		},
		{
			name:   "invalid updateinfo gzip broken",
			repomd: "testdata/fixtures/repomd_valid.xml",
			updateinfos: map[string]string{
				"1": "testdata/fixtures/updateinfo_invalid_gzip.xml.gz",
			},
			hasError: true,
		},
		{
			name:   "invalid updateinfo xml broken",
			repomd: "testdata/fixtures/repomd_valid.xml",
			updateinfos: map[string]string{
				"1": "testdata/fixtures/updateinfo_invalid_xml.xml.gz",
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/releasemd.xml"):
					http.ServeFile(w, r, tt.releasemd)
				case strings.HasSuffix(r.URL.Path, "/mirror.list"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						w.Write([]byte(fmt.Sprintf("http://%s/2018.03/updates/2778354585d0/x86_64", r.Host)))
					case strings.HasPrefix(r.URL.Path, "/2/"):
						w.Write([]byte(fmt.Sprintf("http://%s/2/core/2.0/x86_64/5454bdaaf3e2fa8d3aac354bd0b9f21079f8efbfc8b04fb40db462ed434f9f04", r.Host)))
					case strings.HasPrefix(r.URL.Path, "/core/mirrors/2022"):
						w.Write([]byte(fmt.Sprintf("http://%s/2022/core/guids/b9dbfbda87c463b53ce6de759cc6cb527efa01fc5976bb654b201f294c2d099f/x86_64/", r.Host)))
					}
				case strings.HasSuffix(r.URL.Path, "/repomd.xml"):
					http.ServeFile(w, r, tt.repomd)
				case strings.HasSuffix(r.URL.Path, "/updateinfo.xml.gz"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						http.ServeFile(w, r, tt.updateinfos["1"])
					case strings.HasPrefix(r.URL.Path, "/2/"):
						http.ServeFile(w, r, tt.updateinfos["2"])
					case strings.HasPrefix(r.URL.Path, "/2022/"):
						http.ServeFile(w, r, tt.updateinfos["2022"])
					}
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := amazon.Fetch(
				amazon.WithMirrorURLs(map[string]amazon.MirrorURL{
					"1": {Mirror: fmt.Sprintf("%s/2018.03/updates/x86_64/mirror.list", ts.URL)},
					"2": {Mirror: fmt.Sprintf("%s/2/core/latest/x86_64/mirror.list", ts.URL)},
					"2022": {
						Mirror:    fmt.Sprintf("%s/core/mirrors/%%s/x86_64/mirror.list", ts.URL),
						Releasemd: fmt.Sprintf("%s/core/releasemd.xml", ts.URL),
					},
				}),
				amazon.WithDir(dir), amazon.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				dir, y := filepath.Split(filepath.Clean(dir))
				_, v := filepath.Split(filepath.Clean(dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", v, y, file))
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
