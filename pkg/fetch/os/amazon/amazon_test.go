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
		extra       string
		repomd      map[string]string
		updateinfos map[string]string
		hasError    bool
	}{
		{
			name:  "happy path",
			extra: "testdata/fixtures/extras-catalog_valid.json",
			repomd: map[string]string{
				"1":             "testdata/fixtures/repomd_valid.xml",
				"2":             "testdata/fixtures/repomd_valid.xml",
				"2-emacs":       "testdata/fixtures/repomd_noupdateinfo.xml",
				"2-kernel-5.15": "testdata/fixtures/repomd_valid.xml",
				"2022":          "testdata/fixtures/repomd_valid.xml",
			},
			updateinfos: map[string]string{
				"1":             "testdata/fixtures/updateinfo_1.xml.gz",
				"2":             "testdata/fixtures/updateinfo_2.xml.gz",
				"2-kernel-5.15": "testdata/fixtures/updateinfo_2_kernel-5.15.xml.gz",
				"2022":          "testdata/fixtures/updateinfo_2022.xml.gz",
			},
		},
		{
			name:  "invalid extras-catalog",
			extra: "testdata/fixtures/extras-catalog_invalid.json",
			repomd: map[string]string{
				"2": "testdata/fixtures/repomd_valid.xml",
			},
			updateinfos: map[string]string{
				"2": "testdata/fixtures/updateinfo_2.xml.gz",
			},
			hasError: true,
		},
		{
			name: "invalid repomd",
			repomd: map[string]string{
				"1": "testdata/fixtures/repomd_invalid.xml",
			},
			updateinfos: map[string]string{
				"1": "testdata/fixtures/updateinfo_1.xml.gz",
			},
			hasError: true,
		},
		{
			name: "invalid updateinfo gzip broken",
			repomd: map[string]string{
				"1": "testdata/fixtures/repomd_valid.xml",
			},
			updateinfos: map[string]string{
				"1": "testdata/fixtures/updateinfo_invalid_gzip.xml.gz",
			},
			hasError: true,
		},
		{
			name: "invalid updateinfo xml broken",
			repomd: map[string]string{
				"1": "testdata/fixtures/repomd_valid.xml",
			},
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
				case strings.HasSuffix(r.URL.Path, "/extras-catalog.json"):
					http.ServeFile(w, r, tt.extra)
				case strings.HasSuffix(r.URL.Path, "/mirror.list"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						if _, err := w.Write([]byte(fmt.Sprintf("http://%s/2018.03/updates/2778354585d0/x86_64", r.Host))); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/core/"):
						if _, err := w.Write([]byte(fmt.Sprintf("http://%s/2/core/2.0/x86_64/5454bdaaf3e2fa8d3aac354bd0b9f21079f8efbfc8b04fb40db462ed434f9f04", r.Host))); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/extras/emacs"):
						if _, err := w.Write([]byte(fmt.Sprintf("http://%s/2/extras/emacs/25.3/x86_64/1254dd71e49d635ee063d8842db13fcde9283d5756b7d365860a6985c1c94358", r.Host))); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/extras/kernel-5.15"):
						if _, err := w.Write([]byte(fmt.Sprintf("http://%s/2/extras/kernel-5.15/stable/x86_64/3cea6107e9fffdc60f8ca99c7dac421b427d2ea06003cf5eb970344e4c2e18f4", r.Host))); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/al2022"):
						if _, err := w.Write([]byte(fmt.Sprintf("http://%s/al2022/core/guids/b9dbfbda87c463b53ce6de759cc6cb527efa01fc5976bb654b201f294c2d099f/x86_64/", r.Host))); err != nil {
							t.Error("unexpected error:", err)
						}
					}
				case strings.HasSuffix(r.URL.Path, "/repomd.xml"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						http.ServeFile(w, r, tt.repomd["1"])
					case strings.HasPrefix(r.URL.Path, "/2/core"):
						http.ServeFile(w, r, tt.repomd["2"])
					case strings.HasPrefix(r.URL.Path, "/2/extras/emacs"):
						http.ServeFile(w, r, tt.repomd["2-emacs"])
					case strings.HasPrefix(r.URL.Path, "/2/extras/kernel-5.15"):
						http.ServeFile(w, r, tt.repomd["2-kernel-5.15"])
					case strings.HasPrefix(r.URL.Path, "/al2022/"):
						http.ServeFile(w, r, tt.repomd["2022"])
					}
				case strings.HasSuffix(r.URL.Path, "/updateinfo.xml.gz"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						http.ServeFile(w, r, tt.updateinfos["1"])
					case strings.HasPrefix(r.URL.Path, "/2/core"):
						http.ServeFile(w, r, tt.updateinfos["2"])
					case strings.HasPrefix(r.URL.Path, "/2/extras/kernel-5.15"):
						http.ServeFile(w, r, tt.updateinfos["2-kernel-5.15"])
					case strings.HasPrefix(r.URL.Path, "/al2022/"):
						http.ServeFile(w, r, tt.updateinfos["2022"])
					}
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := amazon.Fetch(
				amazon.WithMirrorURLs(map[string]amazon.MirrorURL{
					"1": {Core: fmt.Sprintf("%s/2018.03/updates/x86_64/mirror.list", ts.URL)},
					"2": {
						Core:  fmt.Sprintf("%s/2/core/latest/x86_64/mirror.list", ts.URL),
						Extra: fmt.Sprintf("%s/2/extras-catalog.json", ts.URL)},
					"2022": {Core: fmt.Sprintf("%s/al2022/core/mirrors/latest/x86_64/mirror.list", ts.URL)},
				}),
				amazon.WithDir(dir), amazon.WithRetry(0))
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
				dir, y := filepath.Split(filepath.Clean(dir))
				dir, repo := filepath.Split(filepath.Clean(dir))
				dir, v := filepath.Split(filepath.Clean(dir))
				if v == "extras" {
					repo = filepath.Join("extras", repo)
					_, v = filepath.Split(filepath.Clean(dir))
				}
				want, err := os.ReadFile(filepath.Join("testdata", "golden", v, repo, y, file))
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
