package data_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/echo/data"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
	"github.com/google/go-cmp/cmp/cmpopts"
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
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
			}))
			dir := t.TempDir()
			err := data.Fetch(data.WithHTTPClient(ts.Client()), data.WithDir(dir), data.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				fn := func(path string) (data.Package, error) {
					f, err := os.Open(path)
					if err != nil {
						return data.Package{}, err
					}
					defer f.Close()

					var v data.Package
					if err := json.UnmarshalRead(f, &v); err != nil {
						return data.Package{}, err
					}
					return v, nil
				}

				// The fetcher emits vulnerabilities in a nondeterministic
				// order, so the files are compared decoded.
				utiltest.DiffFunc(t, filepath.Join("testdata", "golden"), dir, fn,
					cmpopts.SortSlices(func(i, j data.Vulnerability) bool { return i.ID < j.ID }))
			}
		})
	}
}
