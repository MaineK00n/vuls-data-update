package product_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/product"
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
				n := r.URL.Query().Get("$skip")
				if n == "" {
					n = "0"
				}

				bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s.json", n)))
				if err != nil {
					http.NotFound(w, r)
					return
				}

				if _, err := fmt.Fprintf(w, "%s", bytes.ReplaceAll(bs, []byte("https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US/affectedProduct?$skip="), fmt.Appendf(nil, "http://%s/sug/v2.0/sugodata/v2.0/en-US/affectedProduct?$skip=", r.Host))); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "sug/v2.0/sugodata/v2.0/en-US/affectedProduct?$skip=0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = product.Fetch(product.WithDataURL(u), product.WithDir(dir), product.WithRetry(0))
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
