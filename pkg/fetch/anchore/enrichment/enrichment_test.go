package enrichment_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
		}))
		defer ts.Close()

		u, err := url.JoinPath(ts.URL, "anchore", "cve-data-enrichment", "archive", "refs", "heads", "main.tar.gz")
		if err != nil {
			t.Error("unexpected error:", err)
		}

		dir := t.TempDir()
		err = enrichment.Fetch(enrichment.WithDataURL(u), enrichment.WithDir(dir), enrichment.WithRetry(0))
		switch {
		case err != nil && !tt.wantErr:
			t.Error("unexpected error:", err)
		case err == nil && tt.wantErr:
			t.Error("expected error has not occurred")
		case err != nil && tt.wantErr:
			// error was expected and occurred, test passed
			return
		default:
			utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
		}
	}
}
