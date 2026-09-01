package securityreleases_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	securityreleases "github.com/MaineK00n/vuls-data-update/pkg/fetch/apple/security-releases"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			name:     "unexpected_notfound",
			hasError: true,
		},
		{
			name:     "unexpected_host",
			hasError: true,
		},
		{
			name:     "unexpected_empty_list",
			hasError: true,
		},
		{
			name:     "unexpected_table",
			hasError: true,
		},
		{
			// a 6-deep chain of archive pages each linking the next
			name:     "unexpected_deep_crawl",
			hasError: true,
		},
		{
			// an index page whose navigation lists no archive pages
			name:     "unexpected_no_archives",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/en-us/"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "en-us", path.Base(r.URL.Path)))
				case r.URL.Path == "/kb/HT201222":
					http.Redirect(w, r, "/en-us/100100", http.StatusFound)
				case strings.HasPrefix(r.URL.Path, "/kb/"):
					if _, err := os.Stat(filepath.Join("testdata", "fixtures", tt.name, "en-us", path.Base(r.URL.Path))); err != nil {
						http.NotFound(w, r)
						return
					}
					http.Redirect(w, r, path.Join("/en-us", path.Base(r.URL.Path)), http.StatusFound)
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := securityreleases.Fetch(securityreleases.WithBaseURL(fmt.Sprintf("%s/en-us/100100", ts.URL)), securityreleases.WithDir(dir), securityreleases.WithRetry(0), securityreleases.WithConcurrency(2), securityreleases.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden", tt.name), dir, utiltest.WithReplace(ts.URL, "https://support.apple.com"))
			}
		})
	}
}
