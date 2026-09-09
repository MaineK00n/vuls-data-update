package vm_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle/vm"
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
				switch r.URL.Path {
				case "/security/oval/":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "indexof.html"))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "security/oval/")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = vm.Fetch(vm.WithBaseURL(u), vm.WithDir(dir), vm.WithRetry(0), vm.WithConcurrency(1), vm.WithWait(0))
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
