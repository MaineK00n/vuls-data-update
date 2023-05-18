package ovalv2_test

import (
	"fmt"
	"io"
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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat/ovalv2"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name                string
		feedPath            string
		repositoryToCPEPath string
		hasError            bool
	}{
		{
			name:                "happy path",
			feedPath:            "testdata/fixtures/oval/v2/feed.json",
			repositoryToCPEPath: "testdata/fixtures/repository-to-cpe.json",
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

					s := strings.ReplaceAll(string(bs), "https://access.redhat.com/security/data", fmt.Sprintf("http://%s/testdata/fixtures", r.Host))

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

			repositoryToCPEURL, err := url.JoinPath(ts.URL, tt.repositoryToCPEPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = ovalv2.Fetch(ovalv2.WithFeedURL(feedURL), ovalv2.WithRepositoryToCPEURL(repositoryToCPEURL), ovalv2.WithDir(dir), ovalv2.WithRetry(0))
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

				p := filepath.Join("testdata", "golden", "repository-to-cpe.json.gz")
				if !strings.HasSuffix(path, "repository-to-cpe.json.gz") {
					dir, file := filepath.Split(path)
					dir, d := filepath.Split(filepath.Clean(dir))
					dir, stream := filepath.Split(filepath.Clean(dir))
					_, v := filepath.Split(filepath.Clean(dir))
					p = filepath.Join("testdata", "golden", v, stream, d, file)
				}

				want, err := os.ReadFile(p)
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
