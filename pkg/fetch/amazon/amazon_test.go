package amazon_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name        string
		extra       string
		repomd      map[string]string
		updateinfos map[string]string
		// seed is written into the output directory before Fetch, as if left by
		// an earlier run; keep names the seeded paths Fetch must leave in place
		// byte for byte. Everything else seeded must be gone afterwards.
		seed     map[string]string
		keep     []string
		hasError bool
	}{
		{
			name:  "happy path",
			extra: "testdata/fixtures/extras-catalog_valid.json",
			repomd: map[string]string{
				"1":                     "testdata/fixtures/repomd_valid.xml",
				"2":                     "testdata/fixtures/repomd_valid.xml",
				"2-emacs":               "testdata/fixtures/repomd_noupdateinfo.xml",
				"2-kernel-5.15":         "testdata/fixtures/repomd_valid.xml",
				"2023":                  "testdata/fixtures/repomd_valid.xml",
				"2023-kernel-livepatch": "testdata/fixtures/repomd_valid.xml",
				"2023-nvidia":           "testdata/fixtures/repomd_valid.xml",
			},
			updateinfos: map[string]string{
				"1":                     "testdata/fixtures/updateinfo_1.xml.gz",
				"2":                     "testdata/fixtures/updateinfo_2.xml.gz",
				"2-kernel-5.15":         "testdata/fixtures/updateinfo_2_kernel-5.15.xml.gz",
				"2023":                  "testdata/fixtures/updateinfo_2023.xml.gz",
				"2023-kernel-livepatch": "testdata/fixtures/updateinfo_2023_kernel-livepatch.xml.gz",
				"2023-nvidia":           "testdata/fixtures/updateinfo_2023_nvidia.xml.gz",
			},
		},
		{
			// The AL2022 repository is gone from cdn.amazonlinux.com and this
			// fetcher no longer fetches it, so an existing 2022/ is the last copy
			// of those advisories and nothing can rebuild it. A run against a
			// populated checkout has to leave 2022/ and .git in place while still
			// sweeping whatever else an earlier run wrote and this one does not:
			// keeping 2022/ must not turn into keeping everything.
			name:  "keeps the retired 2022/ tree and .git",
			extra: "testdata/fixtures/extras-catalog_valid.json",
			repomd: map[string]string{
				"1":                     "testdata/fixtures/repomd_valid.xml",
				"2":                     "testdata/fixtures/repomd_valid.xml",
				"2-emacs":               "testdata/fixtures/repomd_noupdateinfo.xml",
				"2-kernel-5.15":         "testdata/fixtures/repomd_valid.xml",
				"2023":                  "testdata/fixtures/repomd_valid.xml",
				"2023-kernel-livepatch": "testdata/fixtures/repomd_valid.xml",
				"2023-nvidia":           "testdata/fixtures/repomd_valid.xml",
			},
			updateinfos: map[string]string{
				"1":                     "testdata/fixtures/updateinfo_1.xml.gz",
				"2":                     "testdata/fixtures/updateinfo_2.xml.gz",
				"2-kernel-5.15":         "testdata/fixtures/updateinfo_2_kernel-5.15.xml.gz",
				"2023":                  "testdata/fixtures/updateinfo_2023.xml.gz",
				"2023-kernel-livepatch": "testdata/fixtures/updateinfo_2023_kernel-livepatch.xml.gz",
				"2023-nvidia":           "testdata/fixtures/updateinfo_2023_nvidia.xml.gz",
			},
			seed: map[string]string{
				"2022/core/2021/ALAS2022-2021-001.json": `{"ID": "ALAS2022-2021-001"}`,
				".git/HEAD":                             "ref: refs/heads/main\n",
				"2/core/2000/ALAS2-2000-001.json":       "stale",
				"2024/core/2024/ALAS2024-2024-001.json": "stale",
			},
			keep: []string{"2022/core/2021/ALAS2022-2021-001.json", ".git/HEAD"},
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
						if _, err := fmt.Fprintf(w, "http://%s/2018.03/updates/2778354585d0/x86_64", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/core/"):
						if _, err := fmt.Fprintf(w, "http://%s/2/core/latest/x86_64/5454bdaaf3e2fa8d3aac354bd0b9f21079f8efbfc8b04", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/extras/emacs"):
						if _, err := fmt.Fprintf(w, "http://%s/2/extras/emacs/25.3/x86_64/1254dd71e49d635ee063d8842db13fcde9283d5756b7d365860a6985c1c94358", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/2/extras/kernel-5.15"):
						if _, err := fmt.Fprintf(w, "http://%s/2/extras/kernel-5.15/stable/x86_64/3cea6107e9fffdc60f8ca99c7dac421b427d2ea06003cf5eb970344e4c2e18f4", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/al2023/core"):
						if _, err := fmt.Fprintf(w, "http://%s/al2023/core/guids/b9dbfbda87c463b53ce6de759cc6cb527efa01fc5976bb654b201f294c2d099f/x86_64/", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/al2023/kernel-livepatch"):
						if _, err := fmt.Fprintf(w, "http://%s/al2023/kernel-livepatch/guids/b9dbfbda87c463b53ce6de759cc6cb527efa01fc5976bb654b201f294c2d099f/x86_64/", r.Host); err != nil {
							t.Error("unexpected error:", err)
						}
					case strings.HasPrefix(r.URL.Path, "/al2023/nvidia"):
						if _, err := fmt.Fprintf(w, "http://%s/al2023/nvidia/guids/b9dbfbda87c463b53ce6de759cc6cb527efa01fc5976bb654b201f294c2d099f/x86_64/", r.Host); err != nil {
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
					case strings.HasPrefix(r.URL.Path, "/al2023/core"):
						http.ServeFile(w, r, tt.repomd["2023"])
					case strings.HasPrefix(r.URL.Path, "/al2023/kernel-livepatch"):
						http.ServeFile(w, r, tt.repomd["2023-kernel-livepatch"])
					case strings.HasPrefix(r.URL.Path, "/al2023/nvidia"):
						http.ServeFile(w, r, tt.repomd["2023-nvidia"])
					}
				case strings.HasSuffix(r.URL.Path, "/updateinfo.xml.gz"):
					switch {
					case strings.HasPrefix(r.URL.Path, "/2018.03/"):
						http.ServeFile(w, r, tt.updateinfos["1"])
					case strings.HasPrefix(r.URL.Path, "/2/core"):
						http.ServeFile(w, r, tt.updateinfos["2"])
					case strings.HasPrefix(r.URL.Path, "/2/extras/kernel-5.15"):
						http.ServeFile(w, r, tt.updateinfos["2-kernel-5.15"])
					case strings.HasPrefix(r.URL.Path, "/al2023/core"):
						http.ServeFile(w, r, tt.updateinfos["2023"])
					case strings.HasPrefix(r.URL.Path, "/al2023/kernel-livepatch"):
						http.ServeFile(w, r, tt.updateinfos["2023-kernel-livepatch"])
					case strings.HasPrefix(r.URL.Path, "/al2023/nvidia"):
						http.ServeFile(w, r, tt.updateinfos["2023-nvidia"])
					}
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			for name, content := range tt.seed {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), os.ModePerm); err != nil {
					t.Fatal("unexpected error:", err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0666); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			err := amazon.Fetch(
				amazon.WithMirrorURLs(map[string]amazon.MirrorURL{
					"1": {Core: fmt.Sprintf("%s/2018.03/updates/x86_64/mirror.list", ts.URL)},
					"2": {
						Core:  fmt.Sprintf("%s/2/core/latest/x86_64/mirror.list", ts.URL),
						Extra: fmt.Sprintf("%s/2/extras-catalog.json", ts.URL)},
					"2023": {
						Core:            fmt.Sprintf("%s/al2023/core/mirrors/latest/x86_64/mirror.list", ts.URL),
						KernelLivePatch: fmt.Sprintf("%s/al2023/kernel-livepatch/mirrors/latest/x86_64/mirror.list", ts.URL),
						Nvidia:          fmt.Sprintf("%s/al2023/nvidia/mirrors/latest/x86_64/mirror.list", ts.URL),
					},
				}),
				amazon.WithDir(dir), amazon.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				// The expected tree is golden plus whatever was seeded and must
				// survive. Building it in a temp dir rather than in testdata keeps
				// .git out of the repository, which git refuses to track anyway,
				// and lets one Diff cover all three outcomes: a kept file missing
				// or altered, and a stale file left behind.
				want := filepath.Join("testdata", "golden")
				if len(tt.keep) > 0 {
					want = t.TempDir()
					if err := os.CopyFS(want, os.DirFS(filepath.Join("testdata", "golden"))); err != nil {
						t.Fatal("unexpected error:", err)
					}
					for _, name := range tt.keep {
						if err := os.MkdirAll(filepath.Dir(filepath.Join(want, name)), os.ModePerm); err != nil {
							t.Fatal("unexpected error:", err)
						}
						if err := os.WriteFile(filepath.Join(want, name), []byte(tt.seed[name]), 0666); err != nil {
							t.Fatal("unexpected error:", err)
						}
					}
				}
				if err := utiltest.Diff(want, dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
