package github_test

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

func TestDo(t *testing.T) {
	type response struct {
		Header http.Header `json:"header,omitempty"`
		Query  url.Values  `json:"query,omitempty"`
	}

	type args struct {
		method string
		apiurl string
		token  string
		fn     func(resp *http.Response) error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				method: http.MethodGet,
				apiurl: func() string {
					u, _ := url.Parse("https://api.github.com/")
					u = u.JoinPath("orgs", "vulsio", "packages", "container", "vuls-data-db", "versions")
					q := u.Query()
					q.Set("page", "1")
					q.Set("per_page", "100")
					u.RawQuery = q.Encode()
					return u.String()
				}(),
				token: "token",
				fn: func(resp *http.Response) error {
					var got response
					if err := json.UnmarshalRead(resp.Body, &got); err != nil {
						return err
					}

					expected := response{
						Header: http.Header{
							"Accept":               []string{"application/vnd.github+json"},
							"Accept-Encoding":      []string{"gzip"},
							"Authorization":        []string{"Bearer token"},
							"User-Agent":           []string{"Go-http-client/1.1"},
							"X-Github-Api-Version": []string{"2022-11-28"},
						},
						Query: url.Values{
							"page":     []string{"1"},
							"per_page": []string{"100"},
						},
					}

					if diff := cmp.Diff(expected, got); diff != "" {
						return fmt.Errorf("fn(). (-expected +got):\n%s", diff)
					}

					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				switch r.URL.Path {
				case "/orgs/vulsio/packages/container/vuls-data-db/versions":
					bs, err := json.Marshal(response{Header: r.Header, Query: r.URL.Query()})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					w.WriteHeader(http.StatusOK)
					if _, err := w.Write(bs); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				default:
					http.NotFound(w, r)
				}
			default:
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			}
		}))
		defer ts.Close()

		u, err := url.Parse(tt.args.apiurl)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		uu, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		u.Scheme = uu.Scheme
		u.Host = uu.Host

		t.Run(tt.name, func(t *testing.T) {
			if err := github.Do(tt.args.method, u.String(), tt.args.token, tt.args.fn); (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckScopes(t *testing.T) {
	type args struct {
		token    string
		required []string
	}
	tests := []struct {
		name    string
		args    args
		status  int
		scopes  *string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages, github.ScopeDeletePackages},
			},
			status: http.StatusOK,
			scopes: func() *string {
				s := "delete:packages, gist, read:org, repo, workflow, write:packages"
				return &s
			}(),
		},
		{
			name: "insufficient scopes",
			args: args{
				token:    "token",
				required: []string{github.ScopeWritePackages},
			},
			status: http.StatusOK,
			scopes: func() *string {
				s := "read:packages, repo"
				return &s
			}(),
			wantErr: true,
		},
		{
			name: "no required scopes",
			args: args{
				token: "token",
			},
			status: http.StatusOK,
			scopes: func() *string {
				s := ""
				return &s
			}(),
		},
		{
			name: "scopes are not reported",
			args: args{
				token:    "token",
				required: []string{github.ScopeWritePackages},
			},
			status: http.StatusOK,
		},
		{
			name: "token is not set",
			args: args{
				required: []string{github.ScopeReadPackages},
			},
			status:  http.StatusOK,
			wantErr: true,
		},
		{
			name: "token is invalid",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages},
			},
			status:  http.StatusUnauthorized,
			wantErr: true,
		},
		{
			name: "scopes cannot be fetched",
			args: args{
				token:    "token",
				required: []string{github.ScopeReadPackages},
			},
			status: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/user":
					if tt.scopes != nil {
						w.Header().Set("X-OAuth-Scopes", *tt.scopes)
					}
					w.WriteHeader(tt.status)
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			if err := github.CheckScopes(tt.args.token, tt.args.required, github.WithBaseURL(ts.URL)); (err != nil) != tt.wantErr {
				t.Errorf("CheckScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
