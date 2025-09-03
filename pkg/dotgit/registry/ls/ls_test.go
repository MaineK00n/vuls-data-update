package ls_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
)

func TestList(t *testing.T) {
	type args struct {
		remotes []string
		token   string
	}
	tests := []struct {
		name    string
		args    args
		want    []ls.Response
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				remotes: []string{"org:vulsio/vuls-data-db", "user:vuls/vuls-data-db"},
				token:   "token",
			},
			want: []ls.Response{
				{
					ID:        460898921,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-suse-oval",
					Digest:    "sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673",
					CreatedAt: "2025-07-14T13:05:30Z",
				},
				{
					ID:        460898773,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-vex",
					Digest:    "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb",
					CreatedAt: "2025-07-14T13:05:21Z",
				},
				{
					ID:        460909762,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-fedora",
					Digest:    "sha256:a8c9980b712acd74578c4e52aed513170d92577e3e2d6f53ae2fd25fad1ec7f1",
					CreatedAt: "2025-07-14T13:16:15Z",
				},
				{
					ID:        460900055,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:9e8ddef444ffde76dd764eeb4a5323353e603700f5412c86d0a6fe160a982a28",
					CreatedAt: "2025-07-14T13:06:37Z",
				},
				{
					ID:        460033050,
					Name:      "ghcr.io/vuls/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573af",
					CreatedAt: "2025-07-12T18:34:54Z",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/orgs/vulsio/packages/container/vuls-data-db/versions":
					switch r.URL.Query().Get("page") {
					case "1":
						w.Header().Set("link", `<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=2&per_page=100>; rel="next", <https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=2&per_page=100>; rel="last"`)
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte(`[{"id":460898921,"name":"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673","url":"https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898921","package_html_url":"https://github.com/orgs/vulsio/packages/container/package/vuls-data-db","created_at":"2025-07-14T13:05:30Z","updated_at":"2025-07-14T13:05:30Z","html_url":"https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898921","metadata":{"package_type":"container","container":{"tags":["vuls-data-raw-suse-oval"]}}},{"id":460898773,"name":"sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb","url":"https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898773","package_html_url":"https://github.com/orgs/vulsio/packages/container/package/vuls-data-db","created_at":"2025-07-14T13:05:21Z","updated_at":"2025-07-14T13:05:21Z","html_url":"https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898773","metadata":{"package_type":"container","container":{"tags":["vuls-data-raw-ubuntu-vex"]}}}]`)); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
					case "2":
						w.Header().Set("link", `<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=1&per_page=100>; rel="prev", <https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=1&per_page=100>; rel="first"`)
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte(`[{"id":460909762,"name":"sha256:a8c9980b712acd74578c4e52aed513170d92577e3e2d6f53ae2fd25fad1ec7f1","url":"https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460909762","package_html_url":"https://github.com/orgs/vulsio/packages/container/package/vuls-data-db","created_at":"2025-07-14T13:16:15Z","updated_at":"2025-07-14T13:16:15Z","html_url":"https://github.com/orgs/vulsio/packages/container/vuls-data-db/460909762","metadata":{"package_type":"container","container":{"tags":["vuls-data-raw-fedora"]}}},{"id":460900055,"name":"sha256:9e8ddef444ffde76dd764eeb4a5323353e603700f5412c86d0a6fe160a982a28","url":"https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460900055","package_html_url":"https://github.com/orgs/vulsio/packages/container/package/vuls-data-db","created_at":"2025-07-14T13:06:37Z","updated_at":"2025-07-14T13:06:37Z","html_url":"https://github.com/orgs/vulsio/packages/container/vuls-data-db/460900055","metadata":{"package_type":"container","container":{"tags":["vuls-data-raw-ubuntu-oval"]}}}]`)); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
					default:
						w.Header().Set("link", `<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=2&per_page=100>; rel="prev", <https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=1&per_page=100>; rel="first", <https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=2&per_page=100>; rel="last"`)
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte("[]")); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
					}
				case "/user/packages/container/vuls-data-db/versions":
					switch r.URL.Query().Get("page") {
					case "1":
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte(`[{"id":460033050,"name":"sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573af","url":"https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033050","package_html_url":"https://github.com/users/vuls/packages/container/package/vuls-data-db","created_at":"2025-07-12T18:34:54Z","updated_at":"2025-07-12T18:34:54Z","html_url":"https://github.com/users/vuls/packages/container/vuls-data-db/460033050","metadata":{"package_type":"container","container":{"tags":["vuls-data-raw-ubuntu-oval"]}}}]`)); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
					default:
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte("[]")); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			got, err := ls.List(tt.args.remotes, tt.args.token, ls.WithbaseURL(ts.URL))
			if (err != nil) != tt.wantErr {
				t.Errorf("List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("List() = %v, want %v", got, tt.want)
			}
		})
	}
}
