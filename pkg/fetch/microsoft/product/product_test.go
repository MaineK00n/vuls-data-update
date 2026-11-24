package product_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := r.URL.Query().Get("$skip")
				if n == "" {
					n = "0"
				}

				bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s.json", n)))
				if err != nil {
					http.NotFound(w, r)
					return
				}

				if _, err := fmt.Fprintf(w, "%s", bs); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}))
			dir := t.TempDir()
			err := product.Fetch(product.WithHTTPClient(ts.Client()), product.WithDir(dir), product.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
