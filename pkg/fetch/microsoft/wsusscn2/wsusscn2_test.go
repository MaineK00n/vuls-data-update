package wsusscn2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/wsusscn2"
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
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "microsoftupdate/v6/wsusscan/wsusscn2.cab")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = wsusscn2.Fetch(wsusscn2.WithDataURL(u), wsusscn2.WithDir(dir), wsusscn2.WithRetry(0), wsusscn2.WithConcurrency(2))
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
