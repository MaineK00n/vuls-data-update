package ls_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
)

func TestList(t *testing.T) {
	type args struct {
		repositories []ls.Repository
		token        string
		opts         []ls.Option
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
				repositories: []ls.Repository{
					{
						Type:     "orgs",
						Registry: "ghcr.io",
						Owner:    "vulsio",
						Package:  "vuls-data-db",
					},
					{
						Type:     "users",
						Registry: "ghcr.io",
						Owner:    "vuls",
						Package:  "vuls-data-db",
					},
				},
				token: "token",
			},
			want: []ls.Response{
				{
					ID:        460898921,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-suse-oval",
					Digest:    "sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673",
					CreatedAt: "2025-07-14T13:05:30Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898921",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898921"
						return &s
					}(),
				},
				{
					ID:        460898773,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-vex",
					Digest:    "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb",
					CreatedAt: "2025-07-14T13:05:21Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898773",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898773"
						return &s
					}(),
				},
				{
					ID:        460909762,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-fedora",
					Digest:    "sha256:a8c9980b712acd74578c4e52aed513170d92577e3e2d6f53ae2fd25fad1ec7f1",
					CreatedAt: "2025-07-14T13:16:15Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460909762",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460909762"
						return &s
					}(),
				},
				{
					ID:        460900055,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:9e8ddef444ffde76dd764eeb4a5323353e603700f5412c86d0a6fe160a982a28",
					CreatedAt: "2025-07-14T13:06:37Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460900055",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460900055"
						return &s
					}(),
				},
				{
					ID:        460033050,
					Name:      "ghcr.io/vuls/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573af",
					CreatedAt: "2025-07-12T18:34:54Z",
					URL:       "https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033050",
					HTMLURL: func() *string {
						s := "https://github.com/users/vuls/packages/container/vuls-data-db/460033050"
						return &s
					}(),
				},
				{
					ID:        460033049,
					Name:      "",
					Digest:    "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa",
					CreatedAt: "2025-07-12T06:34:54Z",
					URL:       "https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033049",
					HTMLURL: func() *string {
						s := "https://github.com/users/vuls/packages/container/vuls-data-db/460033049"
						return &s
					}(),
				},
			},
		},
		{
			name: "happy",
			args: args{
				repositories: []ls.Repository{
					{
						Type:     "orgs",
						Registry: "ghcr.io",
						Owner:    "vulsio",
						Package:  "vuls-data-db",
					},
					{
						Type:     "users",
						Registry: "ghcr.io",
						Owner:    "vuls",
						Package:  "vuls-data-db",
					},
				},
				token: "token",
				opts:  []ls.Option{ls.WithTaggedOnly(true)},
			},
			want: []ls.Response{
				{
					ID:        460898921,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-suse-oval",
					Digest:    "sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673",
					CreatedAt: "2025-07-14T13:05:30Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898921",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898921"
						return &s
					}(),
				},
				{
					ID:        460898773,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-vex",
					Digest:    "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb",
					CreatedAt: "2025-07-14T13:05:21Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898773",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898773"
						return &s
					}(),
				},
				{
					ID:        460909762,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-fedora",
					Digest:    "sha256:a8c9980b712acd74578c4e52aed513170d92577e3e2d6f53ae2fd25fad1ec7f1",
					CreatedAt: "2025-07-14T13:16:15Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460909762",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460909762"
						return &s
					}(),
				},
				{
					ID:        460900055,
					Name:      "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:9e8ddef444ffde76dd764eeb4a5323353e603700f5412c86d0a6fe160a982a28",
					CreatedAt: "2025-07-14T13:06:37Z",
					URL:       "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460900055",
					HTMLURL: func() *string {
						s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460900055"
						return &s
					}(),
				},
				{
					ID:        460033050,
					Name:      "ghcr.io/vuls/vuls-data-db:vuls-data-raw-ubuntu-oval",
					Digest:    "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573af",
					CreatedAt: "2025-07-12T18:34:54Z",
					URL:       "https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033050",
					HTMLURL: func() *string {
						s := "https://github.com/users/vuls/packages/container/vuls-data-db/460033050"
						return &s
					}(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/vulsio":
					switch r.Method {
					case http.MethodGet:
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte(`{"login":"vulsio","type":"Organization"}`)); err != nil {
							http.Error(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				case "/users/vuls":
					switch r.Method {
					case http.MethodGet:
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte(`{"login":"vuls","type":"User"}`)); err != nil {
							http.Error(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				case "/orgs/vulsio/packages/container/vuls-data-db/versions", "/users/vuls/packages/container/vuls-data-db/versions":
					switch r.Method {
					case http.MethodGet:
						m := map[string][]ls.Version{
							"/orgs/vulsio/packages/container/vuls-data-db/versions": {
								{
									ID:             460898921,
									Name:           "sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673",
									URL:            "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898921",
									PackageHTMLURL: "https://github.com/orgs/vulsio/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-14T13:05:30Z",
									UpdatedAt:      "2025-07-14T13:05:30Z",
									HTMLURL: func() *string {
										s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898921"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{"vuls-data-raw-suse-oval"},
										},
									},
								},
								{
									ID:             460898773,
									Name:           "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb",
									URL:            "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460898773",
									PackageHTMLURL: "https://github.com/orgs/vulsio/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-14T13:05:21Z",
									UpdatedAt:      "2025-07-14T13:05:21Z",
									HTMLURL: func() *string {
										s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898773"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{"vuls-data-raw-ubuntu-vex"},
										},
									},
								},
								{
									ID:             460909762,
									Name:           "sha256:a8c9980b712acd74578c4e52aed513170d92577e3e2d6f53ae2fd25fad1ec7f1",
									URL:            "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460909762",
									PackageHTMLURL: "https://github.com/orgs/vulsio/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-14T13:16:15Z",
									UpdatedAt:      "2025-07-14T13:16:15Z",
									HTMLURL: func() *string {
										s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460909762"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{"vuls-data-raw-fedora"},
										},
									},
								},
								{
									ID:             460900055,
									Name:           "sha256:9e8ddef444ffde76dd764eeb4a5323353e603700f5412c86d0a6fe160a982a28",
									URL:            "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460900055",
									PackageHTMLURL: "https://github.com/orgs/vulsio/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-14T13:06:37Z",
									UpdatedAt:      "2025-07-14T13:06:37Z",
									HTMLURL: func() *string {
										s := "https://github.com/orgs/vulsio/packages/container/vuls-data-db/460900055"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{"vuls-data-raw-ubuntu-oval"},
										},
									},
								},
							},
							"/users/vuls/packages/container/vuls-data-db/versions": {
								{
									ID:             460033050,
									Name:           "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573af",
									URL:            "https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033050",
									PackageHTMLURL: "https://github.com/users/vuls/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-12T18:34:54Z",
									UpdatedAt:      "2025-07-12T18:34:54Z",
									HTMLURL: func() *string {
										s := "https://github.com/users/vuls/packages/container/vuls-data-db/460033050"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{"vuls-data-raw-ubuntu-oval"},
										},
									},
								},
								{
									ID:             460033049,
									Name:           "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa",
									URL:            "https://api.github.com/users/vuls/packages/container/vuls-data-db/versions/460033049",
									PackageHTMLURL: "https://github.com/users/vuls/packages/container/package/vuls-data-db",
									CreatedAt:      "2025-07-12T06:34:54Z",
									UpdatedAt:      "2025-07-12T06:34:54Z",
									HTMLURL: func() *string {
										s := "https://github.com/users/vuls/packages/container/vuls-data-db/460033049"
										return &s
									}(),
									Metadata: &ls.Metadata{
										PackageType: "container",
										Container: &ls.Container{
											Tags: []string{},
										},
									},
								},
							},
						}

						perpage := 2

						page := func() int {
							i, err := strconv.Atoi(r.URL.Query().Get("page"))
							if err != nil {
								return 1
							}
							if i < 1 {
								return 1
							}
							return i
						}()

						vs, ok := m[r.URL.Path]
						if !ok {
							http.Error(w, fmt.Sprintf("%s not found", r.URL.Path), http.StatusInternalServerError)
							return
						}

						w.Header().Set("link", func() string {
							last := func() int {
								if len(vs)%perpage == 0 {
									return len(vs) / perpage
								}
								return len(vs)/perpage + 1
							}()

							var ss []string
							if page < last {
								ss = append(ss, fmt.Sprintf(`<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=%d&per_page=%d>; rel="next"`, page+1, perpage))
							}
							if page > 1 {
								ss = append(ss, fmt.Sprintf(`<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=%d&per_page=%d>; rel="prev"`, page-1, perpage))
							}
							if page != 1 {
								ss = append(ss, fmt.Sprintf(`<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=%d&per_page=%d>; rel="first"`, 1, perpage))
							}
							if page != last {
								ss = append(ss, fmt.Sprintf(`<https://api.github.com/organizations/54834211/packages/container/vuls-data-db/versions?page=%d&per_page=%d>; rel="last"`, last, perpage))
							}
							return strings.Join(ss, ", ")
						}())
						w.WriteHeader(http.StatusOK)
						if err := json.NewEncoder(w).Encode(func() []ls.Version {
							start := (page - 1) * perpage
							end := start + perpage

							if start >= len(vs) {
								return []ls.Version{}
							}
							if end > len(vs) {
								return vs[start:]
							}
							return vs[start:end]
						}()); err != nil {
							http.Error(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			got, err := ls.List(tt.args.repositories, tt.args.token, append([]ls.Option{ls.WithbaseURL(ts.URL)}, tt.args.opts...)...)
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
