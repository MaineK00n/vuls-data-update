package untag_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/go-digest"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/untag"
)

type manifest struct {
	id     uint32
	digest string
}

type user struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

func TestUntag(t *testing.T) {
	type args struct {
		imageRef string
		token    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				imageRef: "ghcr.io/test-owner/test-pack:existing-tag",
				token:    "token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, _, _ := strings.Cut(strings.TrimPrefix(tt.args.imageRef, "ghcr.io/"), ":")
			owner, pack, _ := strings.Cut(repo, "/")
			ms := make(map[string]manifest)
			tag2digest := make(map[string]string)

			reg := registry.New()

			h := func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == fmt.Sprintf("/users/%s", owner):
					switch r.Method {
					case http.MethodGet:
						w.WriteHeader(http.StatusOK)
						if err := json.MarshalWrite(w, user{Login: owner, Type: "Organization"}); err != nil {
							t.Errorf("write response: %v", err)
						}
					default:
						t.Errorf("unexpected request received. method: %s, URL: %s", r.Method, r.URL.String())
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				case strings.HasPrefix(r.URL.Path, fmt.Sprintf("/orgs/%s/packages/container/%s/versions", owner, pack)):
					switch r.Method {
					case http.MethodGet:
						vs := make([]ls.Version, 0, len(ms))
						tags := make(map[string][]string)
						for t, d := range tag2digest {
							tags[d] = append(tags[d], t)
						}
						for d, m := range ms {
							vs = append(vs, ls.Version{
								ID:   int(m.id),
								Name: d,
								URL:  fmt.Sprintf("https://api.github.com/orgs/%s/packages/container/%s/versions/%d", owner, pack, m.id),
								Metadata: &ls.Metadata{
									PackageType: "container",
									Container: &ls.Container{
										Tags: tags[d],
									},
								},
							})
						}

						w.WriteHeader(http.StatusOK)
						if err := json.MarshalWrite(w, vs); err != nil {
							t.Errorf("write response: %v", err)
						}
					case http.MethodDelete:
						id := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/orgs/%s/packages/container/%s/versions/", owner, pack))
						maps.DeleteFunc(ms, func(d string, m manifest) bool {
							return fmt.Sprintf("%d", m.id) == id
						})

						w.WriteHeader(http.StatusNoContent)
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}

				case strings.HasPrefix(r.URL.Path, fmt.Sprintf("/v2/%s/%s/manifests/sha256:", owner, pack)):
					d := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/v2/%s/%s/manifests/", owner, pack))
					switch r.Method {
					case http.MethodPut:
						if _, ok := ms[d]; !ok {
							ms[d] = manifest{
								id:     uint32(len(ms) + 1),
								digest: d,
							}
						}
					default:
					}
					reg.ServeHTTP(w, r)

				case strings.HasPrefix(r.URL.Path, fmt.Sprintf("/v2/%s/%s/manifests/", owner, pack)):
					switch r.Method {
					case http.MethodPut:
						bs, err := io.ReadAll(r.Body)
						if err != nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}
						d := digest.FromBytes(bs).String()
						r.Body = io.NopCloser(bytes.NewReader(bs))

						if _, ok := ms[d]; !ok {
							ms[d] = manifest{
								id:     uint32(len(ms) + 1), // assume manifest is deleted only once and at last
								digest: d,
							}
						}

						tag2digest[strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/v2/%s/%s/manifests/", owner, pack))] = d
					default:
					}
					reg.ServeHTTP(w, r)
				default:
					reg.ServeHTTP(w, r)
				}
			}

			ts := httptest.NewTLSServer(http.HandlerFunc(h))
			defer ts.Close()

			originalTransport := http.DefaultTransport
			http.DefaultTransport = ts.Client().Transport
			defer func() {
				http.DefaultTransport = originalTransport
			}()

			for tag, content := range map[string]string{
				"not-to-be-deleted": "foo",
				"existing-tag":      "bar",
			} {
				u, err := url.Parse(fmt.Sprintf("%s/v2/%s/%s/manifests/%s", ts.URL, owner, pack, tag))
				if err != nil {
					t.Fatalf("parse url: %v", err)
				}
				req, err := http.NewRequest(http.MethodPut, u.String(), io.NopCloser(strings.NewReader(content)))
				if err != nil {
					t.Fatalf("create request: %v", err)
				}
				req.Header.Set("Content-Type", "text/plain")
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatalf("put manifest: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("unexpected status: %d", resp.StatusCode)
				}
			}

			err := untag.Untag(tt.args.imageRef, tt.args.token, untag.WithGitHubAPIURL(ts.URL), untag.WithRegistryHost(strings.TrimPrefix(ts.URL, "https://")))
			if (err != nil) != tt.wantErr {
				t.Errorf("Untag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			rs, err := ls.List([]ls.Repository{{Type: "orgs", Registry: "ghcr.io", Owner: owner, Package: pack}}, tt.args.token, ls.WithbaseURL(ts.URL))
			if err != nil {
				t.Errorf("List() error = %v", err)
				return
			}

			if slices.IndexFunc(rs, func(r ls.Response) bool { return r.Name == tt.args.imageRef }) != -1 {
				t.Errorf("tag still exists. tag: %s", tt.args.imageRef)
			}

			if slices.IndexFunc(rs, func(r ls.Response) bool { return r.Name == fmt.Sprintf("ghcr.io/%s/%s:not-to-be-deleted", owner, pack) }) == -1 {
				t.Errorf("wrong tag deleted. tag: %s", fmt.Sprintf("ghcr.io/%s/%s:not-to-be-deleted", owner, pack))
			}
		})
	}
}
