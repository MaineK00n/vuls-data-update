package v1_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v1"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		feeds    []string
		hasError bool
	}{
		{
			name:  "happy path",
			feeds: []string{"2002", "2021", "modified"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
			}))

			dir := t.TempDir()
			err := v1.Fetch(v1.WithHTTPClient(ts.Client()), v1.WithFeeds(tt.feeds), v1.WithDir(dir), v1.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
