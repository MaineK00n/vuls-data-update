package csaf_test

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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/siemens/csaf"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "ssa-feed-tlp-white.json":
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
					if err != nil {
						http.NotFound(w, r)
					}
					defer f.Close()

					bs, err := io.ReadAll(f)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}

					s := strings.ReplaceAll(string(bs), "https://cert-portal.siemens.com", fmt.Sprintf("http://%s", r.Host))

					http.ServeContent(w, r, "ssa-feed-tlp-white.json", time.Now(), strings.NewReader(s))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "productcert/csaf/ssa-feed-tlp-white.json")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = csaf.Fetch(csaf.WithDataURL(u), csaf.WithDir(dir), csaf.WithRetry(1))
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
