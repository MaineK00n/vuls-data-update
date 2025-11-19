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
