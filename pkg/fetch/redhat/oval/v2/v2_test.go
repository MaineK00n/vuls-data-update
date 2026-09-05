package v2_test

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

	v2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v2"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		feedPath string
		hasError bool
	}{
		{
			name:     "happy path",
			feedPath: "testdata/fixtures/oval/v2/feed.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "feed.json":
					f, err := os.Open(strings.TrimPrefix(r.URL.Path, "/"))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					s := strings.ReplaceAll(string(bs), "https://security.access.redhat.com/data", fmt.Sprintf("http://%s/testdata/fixtures", r.Host))

					http.ServeContent(w, r, "feed.json", time.Now(), strings.NewReader(s))
				default:
					http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
				}
			}))
			defer ts.Close()

			feedURL, err := url.JoinPath(ts.URL, tt.feedPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = v2.Fetch(v2.WithFeedURL(feedURL), v2.WithDir(dir), v2.WithRetry(0))
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
