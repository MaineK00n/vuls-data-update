package tag_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/remote/tag"
)

func TestTag(t *testing.T) {
	type args struct {
		imageRef string
		newTag   string
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
				newTag:   "new-tag",
				token:    "token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			putCalled := false

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/v2/test-owner/test-pack/manifests/existing-tag" {
					m := ocispec.Manifest{
						Config: ocispec.Descriptor{
							MediaType: "application/vnd.oci.empty.v1+json",
							Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
							Size:      2,
						},
						Layers: []ocispec.Descriptor{
							{
								MediaType: "application/vnd.oci.empty.v1+json",
								Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
								Size:      2,
							},
							{
								MediaType: "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
								Digest:    "sha256:e62d41a3f65fc082f200b11ba82c989b2a62d90ec6dd132bd1f131ced07c30d3",
								Size:      100325544,
							},
						},
						MediaType: ocispec.MediaTypeImageManifest,
					}
					manifestBytes, err := json.Marshal(m)
					if err != nil {
						t.Errorf("marshal manifest: %v", err)
					}

					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Docker-Content-Digest", "sha256:f58673caf2600d4f0446dd8729b6afe3d1d1d5222692d7ce3c2b839c5cc5c2d9")
					w.WriteHeader(http.StatusOK)
					_, err = w.Write(manifestBytes)
					if err != nil {
						t.Errorf("write response: %v", err)
					}
					return
				}

				if r.Method == http.MethodPut && r.URL.Path == "/v2/test-owner/test-pack/manifests/new-tag" {
					_, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read request body: %v", err)
					}

					w.Header().Set("Location", r.URL.Path)
					w.WriteHeader(http.StatusCreated)
					putCalled = true
					return
				}

				t.Errorf("Unexpected request received. method: %s, URL: %s", r.Method, r.URL.String())
				http.Error(w, "Bad Request", http.StatusBadRequest)
			}))
			defer server.Close()

			originalTransport := http.DefaultTransport
			defer func() {
				http.DefaultTransport = originalTransport
			}()
			http.DefaultTransport = server.Client().Transport

			err := tag.Tag(strings.Replace(tt.args.imageRef, "ghcr.io", strings.TrimPrefix(server.URL, "https://"), 1), tt.args.newTag, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Tag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !putCalled {
				t.Errorf("PUT manifests with \"new-tag\" API have not called.")
			}
		})
	}
}
