package enrichment_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/anchore/enrichment"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type args struct {
		_ []enrichment.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{},
		},
	}
	for _, tt := range tests {
		ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
		}))
		dir := t.TempDir()
		err := enrichment.Fetch(enrichment.WithHTTPClient(ts.Client()), enrichment.WithDir(dir), enrichment.WithRetry(0))
		switch {
		case err != nil && !tt.wantErr:
			t.Error("unexpected error:", err)
		case err == nil && tt.wantErr:
			t.Error("expected error has not occurred")
		case err == nil:
			utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
		}
	}
}
