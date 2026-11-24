package delete_test

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/delete"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
)

func TestDelete(t *testing.T) {
	type args struct {
		images []string
		token  string
		opts   []delete.Option
	}
	tests := []struct {
		name string
		args args
		// afterList changes the versions once the first listing has been
		// answered, as another client does while Delete works through the
		// images.
		afterList func(vs []ls.Version) []ls.Version
		// deleteNotFound makes the DELETE of these ids answer 404 without
		// deleting, as GitHub may answer a token that can read the version but
		// not delete it.
		deleteNotFound []int
		// deleteGone makes the DELETE of these ids delete and answer 404, as
		// an attempt the API client retried after the first went through is
		// answered.
		deleteGone []int
		// deleteForbidden makes the DELETE of these ids answer 403.
		deleteForbidden []int
		// deleteRateLimited makes the DELETE of these ids answer the primary
		// rate limit, which resets later than the API client waits for.
		deleteRateLimited []int
		wantErr           bool
		// wantErrContains are parts of the error.
		wantErrContains []string
		// wantRemaining are the digests left in the registry.
		wantRemaining []string
	}{
		{
			name: "untagged",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "tagged",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
				token:  "token",
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "tagged, but force",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
				token:  "token",
				opts:   []delete.Option{delete.WithForce(true)},
			},
			wantRemaining: []string{"sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "several",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
		},
		{
			name: "several, one of them tagged",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
		},
		{
			name: "several, one of them not found",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:0000000000000000000000000000000000000000000000000000000000000000", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "tagged after the listing",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			afterList: func(vs []ls.Version) []ls.Version {
				for i := range vs {
					if vs[i].Name == "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa" {
						vs[i].Metadata.Container.Tags = []string{"vuls-data-raw-test"}
					}
				}
				return vs
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "deleted by another client after the listing",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			afterList: func(vs []ls.Version) []ls.Version {
				return slices.DeleteFunc(vs, func(v ls.Version) bool {
					return v.Name == "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"
				})
			},
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
		},
		{
			name: "the delete answers 404, and the version is gone",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			deleteGone:    []int{460898773},
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "the delete answers 404, but the version is still there",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			deleteNotFound:  []int{460898773},
			wantErr:         true,
			wantErrContains: []string{"yet the version is still there"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "several, the delete of one of them refused",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			deleteForbidden: []int{460898773},
			wantErr:         true,
			wantErrContains: []string{"actual: 403"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
		},
		{
			name: "the id names another digest by the time it is read",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			afterList: func(vs []ls.Version) []ls.Version {
				for i := range vs {
					if vs[i].ID == 460898773 {
						vs[i].Name = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
					}
				}
				return vs
			},
			wantErr:         true,
			wantErrContains: []string{"unexpected version digest"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:0000000000000000000000000000000000000000000000000000000000000000", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "a package that cannot be listed does not stop the others",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db-backup@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db-backup@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa", "ghcr.io/vulsio/vuls-data-db@sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673"},
				token:  "token",
			},
			wantErr:         true,
			wantErrContains: []string{"delete the images of vulsio/vuls-data-db-backup. list versions", "refuse to delete a tagged version"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "an owner that cannot be looked up does not stop the others",
			args: args{
				images: []string{"ghcr.io/unknown/a@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/unknown/b@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantErr:         true,
			wantErrContains: []string{"delete the images of unknown/a. get the type of unknown", "delete the images of unknown/b. get the type of unknown"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "a rate limit stops the rest",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			deleteRateLimited: []int{460898773},
			wantErr:           true,
			wantErrContains:   []string{"stop at a GitHub rate limit", "API rate limit exceeded"},
			wantRemaining:     []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "a rate limit on a listing stops the rest",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db-limited@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantErr:         true,
			wantErrContains: []string{"stop at a GitHub rate limit", "delete the images of vulsio/vuls-data-db-limited. list versions"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "a rate limit on the lookup of an owner stops the rest",
			args: args{
				images: []string{"ghcr.io/limited/a@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantErr:         true,
			wantErrContains: []string{"stop at a GitHub rate limit", "get the type of limited"},
			wantRemaining:   []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "the same digest twice",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb"},
				token:  "token",
			},
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "no digest",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db"},
				token:  "token",
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
		},
		{
			name: "not ghcr.io",
			args: args{
				images: []string{"ghcr.io/vulsio/vuls-data-db@sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "docker.io/vulsio/vuls-data-db@sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
				token:  "token",
			},
			wantErr:       true,
			wantRemaining: []string{"sha256:6413c62920ab027e680d7adf44bec195e9f2ec7a299140ff9a5d2193a626b673", "sha256:6cb985595c5e29861b266ae89ac42946dc5451557b8fd949ad08df12f9615efb", "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa"},
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
					HTMLURL:        new("https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898921"),
					Metadata: &ls.Metadata{
						PackageType: "container",
						Container: &ls.Container{
							Tags: []string{"vuls-data-raw-suse-oval", "vuls-data-raw-suse-oval-alias"},
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
					HTMLURL:        new("https://github.com/orgs/vulsio/packages/container/vuls-data-db/460898773"),
					Metadata: &ls.Metadata{
						PackageType: "container",
						Container:   &ls.Container{},
					},
				},
				{
					ID:             460033049,
					Name:           "sha256:29c88e701ac502d431e318a82b327d73f220b82714852b6942bcaffbb4e573aa",
					URL:            "https://api.github.com/orgs/vulsio/packages/container/vuls-data-db/versions/460033049",
					PackageHTMLURL: "https://github.com/orgs/vulsio/packages/container/package/vuls-data-db",
					CreatedAt:      "2025-07-12T06:34:54Z",
					UpdatedAt:      "2025-07-12T06:34:54Z",
					HTMLURL:        new("https://github.com/orgs/vulsio/packages/container/vuls-data-db/460033049"),
					Metadata: &ls.Metadata{
						PackageType: "container",
						Container:   &ls.Container{},
					},
				},
			}

			// listings counts the listings Delete starts, which is the
			// requests of their first page, and lookups the lookups of each
			// owner.
			var listings int
			lookups := make(map[string]int)
			// limited tells that a request was answered with a rate limit,
			// after which Delete sends nothing more.
			var limited bool
			rateLimit := func(w http.ResponseWriter) {
				limited = true
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
				http.Error(w, `{"message":"API rate limit exceeded for installation."}`, http.StatusForbidden)
			}
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if limited {
					t.Errorf("Delete() sent %s %s after a rate limit", r.Method, r.URL.Path)
				}
				if owner, ok := strings.CutPrefix(r.URL.Path, "/users/"); ok {
					lookups[owner]++
				}
				switch r.URL.Path {
				case "/users/limited", "/orgs/vulsio/packages/container/vuls-data-db-limited/versions":
					rateLimit(w)
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

						if page == 1 {
							listings++
							if listings == 1 && tt.afterList != nil {
								vs = tt.afterList(vs)
							}
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				case "/orgs/vulsio/packages/container/vuls-data-db/versions/460898921",
					"/orgs/vulsio/packages/container/vuls-data-db/versions/460898773",
					"/orgs/vulsio/packages/container/vuls-data-db/versions/460033049":
					id, err := strconv.Atoi(path.Base(r.URL.Path))
					if err != nil {
						http.Error(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
						return
					}
					i := slices.IndexFunc(vs, func(v ls.Version) bool { return v.ID == id })

					switch r.Method {
					case http.MethodGet:
						if i == -1 {
							http.NotFound(w, r)
							return
						}
						w.WriteHeader(http.StatusOK)
						if err := json.MarshalWrite(w, vs[i]); err != nil {
							http.Error(w, fmt.Sprintf("unexpected error: %v", err), http.StatusInternalServerError)
						}
					case http.MethodDelete:
						switch {
						case slices.Contains(tt.deleteForbidden, id):
							http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
						case slices.Contains(tt.deleteRateLimited, id):
							rateLimit(w)
						case i == -1 || slices.Contains(tt.deleteNotFound, id):
							// As GHCR does, answer 404 for a version that is
							// already gone.
							http.NotFound(w, r)
						case slices.Contains(tt.deleteGone, id):
							vs = slices.Delete(vs, i, i+1)
							http.NotFound(w, r)
						default:
							vs = slices.Delete(vs, i, i+1)
							w.WriteHeader(http.StatusNoContent)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			// The in-memory network routes api.github.com to the test server,
			// so the default production base URL is used.
			err := delete.Delete(tt.args.images, tt.args.token, append(tt.args.opts, delete.WithHTTPClient(ts.Client()))...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, s := range tt.wantErrContains {
				if err == nil || !strings.Contains(err.Error(), s) {
					t.Errorf("Delete() error = %v, want it to contain %q", err, s)
				}
			}

			// The versions of a package are listed once, however many of its
			// images are deleted, unless an image is refused before anything
			// is sent.
			if listings > 1 {
				t.Errorf("Delete() listed the versions %d times, want at most once", listings)
			}
			for owner, n := range lookups {
				if n > 1 {
					t.Errorf("Delete() looked %s up %d times, want at most once", owner, n)
				}
			}

			remaining := make([]string, 0, len(vs))
			for _, v := range vs {
				remaining = append(remaining, v.Name)
			}
			if diff := cmp.Diff(tt.wantRemaining, remaining); diff != "" {
				t.Errorf("Delete() remaining digests. (-expected +got):\n%s", diff)
			}
		})
	}
}
