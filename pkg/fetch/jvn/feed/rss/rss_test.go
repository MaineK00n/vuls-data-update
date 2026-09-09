package rss_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/rss"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/checksum.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case path.Base(r.URL.Path) == "checksum.txt":
					f, err := os.Open(strings.TrimPrefix(r.URL.Path, "/"))
					if err != nil {
						http.NotFound(w, r)
						return
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					s := strings.NewReplacer("https://jvndb.jvn.jp/ja/rss/years", fmt.Sprintf("http://%s/testdata/fixtures", r.Host), "https://jvndb.jvn.jp/ja/rss", fmt.Sprintf("http://%s/testdata/fixtures", r.Host)).Replace(string(bs))

					http.ServeContent(w, r, "checksum.txt", time.Now(), strings.NewReader(s))
				case strings.HasPrefix(r.URL.Path, "/at/"):
					// Real JPCERT-AT alert page saved under testdata/fixtures.
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", strings.TrimPrefix(r.URL.Path, "/")))
				default:
					f, err := os.Open(strings.TrimPrefix(r.URL.Path, "/"))
					if err != nil {
						http.NotFound(w, r)
						return
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Rewrite JPCERT-AT reference URLs so they are fetched from this
					// test server instead of the real host.
					s := strings.ReplaceAll(string(bs), "https://www.jpcert.or.jp", fmt.Sprintf("http://%s", r.Host))

					http.ServeContent(w, r, path.Base(r.URL.Path), time.Now(), strings.NewReader(s))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdata)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = rss.Fetch(rss.WithDataURL(u), rss.WithDir(dir), rss.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir, utiltest.WithReplace(ts.URL, "https://www.jpcert.or.jp"))
			}
		})
	}
}
