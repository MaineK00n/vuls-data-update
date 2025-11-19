package delete_test

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/delete"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
)

func TestDelete(t *testing.T) {
	type args struct {
		image string
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				image: "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb",
				token: "token",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := []ls.Version{
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
			}

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
				case "/orgs/vulsio/packages/container/vuls-data-db/versions":
					switch r.Method {
					case http.MethodGet:
						perpage := func() int {
							i, err := strconv.Atoi(r.URL.Query().Get("per_page"))
							if err != nil {
								return 30
							}
							if i < 1 || i > 100 {
								return 30
							}
							return i
						}()

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
						if err := json.MarshalWrite(w, func() []ls.Version {
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
				case "/orgs/vulsio/packages/container/vuls-data-db/versions/460898773":
					switch r.Method {
					case http.MethodDelete:
						vs = slices.DeleteFunc(vs, func(v ls.Version) bool {
							return v.ID == 460898773
						})
						w.WriteHeader(http.StatusNoContent)
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			if err := delete.Delete(tt.args.image, tt.args.token, delete.WithAPIEndpoint(delete.APIEndpoint{GitHub: &delete.GitHub{BaseURL: ts.URL}})); (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}

			rs, err := ls.List([]ls.Repository{{Type: "orgs", Registry: "ghcr.io", Owner: "vulsio", Package: "vuls-data-db"}}, tt.args.token, ls.WithbaseURL(ts.URL))
			if err != nil {
				t.Errorf("List() error = %v", err)
			}

			if slices.ContainsFunc(rs, func(r ls.Response) bool { return strings.HasSuffix(tt.args.image, r.Digest) }) {
				t.Errorf("Delete() seems not to have deleted the version with digest %q, remaining versions: %+v", tt.args.image, rs)
			}
		})
	}
}
