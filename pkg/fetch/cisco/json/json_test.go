package json_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/json"
)

func TestFetch(t *testing.T) {
	type args struct {
		id     string
		secret string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				id:     "id",
				secret: "secret",
			},
		},
		{
			name: "invalid client id",
			args: args{
				id:     "invalid_id",
				secret: "secret",
			},
			hasError: true,
		},
		{
			name: "invalid client secret",
			args: args{
				id:     "id",
				secret: "invalid_secret",
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth2/default/v1/token":
					if err := r.ParseForm(); err != nil {
						w.WriteHeader(http.StatusBadRequest)
						if _, err := fmt.Fprintf(w, `{"error": %s}`, err); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}

					if id := r.PostFormValue("client_id"); id != "id" {
						w.WriteHeader(http.StatusBadRequest)
						if _, err := fmt.Fprintf(w, `{"errorCode":"invalid_client","errorSummary":"Invalid value for 'client_id' parameter.","errorLink":"invalid_client","errorId":"%s","errorCauses":[]}`, id); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}

					if secret := r.PostFormValue("client_secret"); secret != "secret" {
						w.WriteHeader(http.StatusUnauthorized)
						if _, err := fmt.Fprintf(w, `{"error":"invalid_client","error_description":"The client secret supplied for a confidential client is invalid."}`); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}

					w.WriteHeader(http.StatusOK)
					if _, err := fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"token","scope":"customscope"}`); err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				case "/security/advisories/v2/all":
					auth := r.Header.Get("Authorization")
					if auth == "" {
						w.WriteHeader(http.StatusForbidden)
						if _, err := fmt.Fprintf(w, "<h1>Authorization Header is either empty or not found in request</h1>"); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}

					if auth != "Bearer token" {
						w.WriteHeader(http.StatusForbidden)
						if _, err := fmt.Fprintf(w, "<h1>Token expired</h1>"); err != nil {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}

					http.ServeFile(w, r, "testdata/fixtures/all.json")
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := json.Fetch(tt.args.id, tt.args.secret, json.WithAccessTokenURL(fmt.Sprintf("%s/oauth2/default/v1/token", ts.URL)), json.WithAPIURL(fmt.Sprintf("%s/security/advisories/v2/all", ts.URL)), json.WithDir(dir), json.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", dir, file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}
			}
		})
	}
}
