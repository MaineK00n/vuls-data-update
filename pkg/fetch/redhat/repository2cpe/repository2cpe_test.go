package repository2cpe_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name                string
		repositoryToCPEPath string
		hasError            bool
	}{
		{
			name:                "happy path",
			repositoryToCPEPath: "testdata/fixtures/repository-to-cpe.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.repositoryToCPEPath)
			}))
			dir := t.TempDir()
			err := repository2cpe.Fetch(repository2cpe.WithHTTPClient(ts.Client()), repository2cpe.WithDir(dir), repository2cpe.WithRetry(0))
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
