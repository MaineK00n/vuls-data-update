package untag_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/remote/untag"
)

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
			deleteCalled := false

			// some data are needed to later API calls, place them in this scope
			var dummyManifestBytes []byte
			var dummyManifestDigest string

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("[server] r.Method: %s, r.URL.Path: %s\n", r.Method, r.URL.Path)

				if r.Method == http.MethodGet && r.URL.Path == "/users/test-owner" {
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write([]byte(`{"login": "test-owner", "type": "Organization"}`)); err != nil {
						t.Errorf("write response: %v", err)
					}
					return
				}

				if r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/v2/test-owner/test-pack/blobs/sha256:") {
					w.Header().Set("Content-Length", fmt.Sprintf("%d", 42))
					w.Header().Set("Docker-Content-Digest", strings.TrimPrefix(r.URL.Path, "/v2/test-owner/test-pack/blobs/"))
					w.WriteHeader(http.StatusOK)
					return
				}

				if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v2/test-owner/test-pack/manifests/") {
					bin, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read request body: %v", err)
					}

					w.Header().Set("Location", r.URL.Path)
					w.WriteHeader(http.StatusCreated)

					dummyManifestBytes = bin
					return
				}

				if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/test-owner/test-pack/manifests/") {
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Docker-Content-Digest", func() string { _, file := path.Split(r.URL.Path); return file }())
					w.WriteHeader(http.StatusOK)
					_, err := w.Write(dummyManifestBytes)
					if err != nil {
						t.Errorf("write response: %v", err)
					}

					dummyManifestDigest = strings.TrimPrefix(r.URL.Path, "/v2/test-owner/test-pack/manifests/")
					return
				}

				if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/orgs/test-owner/packages/container/test-pack/versions") {
					w.WriteHeader(http.StatusOK)
					if _, err := fmt.Fprintf(w, `[
              {
                "id": 499636231,
                "name": %q,
                "url": "https://api.github.com/orgs/test-owner/packages/container/test-pack/versions/499636231",
                "package_html_url": "https://github.com/orgs/test-owner/packages/container/package/test-pack",
                "created_at": "2025-08-29T02:18:22Z",
                "updated_at": "2025-08-29T02:18:22Z",
                "html_url": "https://github.com/orgs/test-owner/packages/container/test-pack/499636231",
                "metadata": {
                  "package_type": "container",
                  "container": {
                    "tags": [
                      "existing-tag"
                    ]
                  }
                }
              }
	        ]`, dummyManifestDigest); err != nil {
						t.Errorf("write response: %v", err)
					}
					return
				}

				if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/orgs/test-owner/packages/container/test-pack/versions") {
					w.WriteHeader(http.StatusNoContent)

					deleteCalled = true
					return
				}

				t.Errorf("unexpected request received. method: %s, URL: %s", r.Method, r.URL.String())
				http.Error(w, "Bad Request", http.StatusBadRequest)
			}))
			defer server.Close()

			originalTransport := http.DefaultTransport
			defer func() {
				http.DefaultTransport = originalTransport
			}()
			http.DefaultTransport = server.Client().Transport

			err := untag.Untag(tt.args.imageRef, tt.args.token, untag.WithBaseAPIURL(server.URL), untag.WithOrasHost(strings.TrimPrefix(server.URL, "https://")))
			if (err != nil) != tt.wantErr {
				t.Errorf("Untag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !deleteCalled {
				t.Errorf("DELETE versions GitHub API have not called.")
			}
		})
	}
}
