package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/endoflife-date/api"
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
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
		}))
		defer ts.Close()

		u, err := url.JoinPath(ts.URL, "api/v1/products/full")
		if err != nil {
			t.Error("unexpected error:", err)
		}

		dir := t.TempDir()
		err = api.Fetch(api.WithBaseURL(u), api.WithDir(dir), api.WithRetry(0), api.WithConcurrency(1), api.WithWait(0))
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
	}
}
