package list_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/enisa/euvd/list"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type args struct {
		opts []list.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				opts: []list.Option{list.WithConcurrency(1)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "search":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s_%s.json", r.URL.Query().Get("page"), r.URL.Query().Get("size"))))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "api", "search")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			opts := append([]list.Option{list.WithBaseURL(u), list.WithDir(dir)}, tt.args.opts...)
			err = list.Fetch(opts...)
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
		})
	}
}
