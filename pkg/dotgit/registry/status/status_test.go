package status_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/status"
)

func generateDescriptor(mediaType string, blob []byte) (desc ocispec.Descriptor) {
	desc = ocispec.Descriptor{ // Generate descriptor based on the media type and blob content
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob), // Calculate digest
		Size:      int64(len(blob)),       // Include blob size
	}
	return desc
}

func generateManifestContent(config ocispec.Descriptor, layers ...ocispec.Descriptor) ([]byte, error) {
	content := ocispec.Manifest{
		Config:    config, // Set config blob
		Layers:    layers, // Set layer blobs
		Versioned: specs.Versioned{SchemaVersion: 2},
	}
	return json.Marshal(content) // Get json content
}

func TestStatus(t *testing.T) {
	type args struct {
		repository string
	}
	tests := []struct {
		name    string
		args    args
		want    status.RepoStatus
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
			want: status.RepoStatus{
				Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				Layer: ocispec.Descriptor{
					MediaType: "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
					Digest:    "sha256:6d7d8bb5bf7c01b007c53a0e44625f69c6ee121c87a92cdabd35cdcb99b3fa2f",
					Size:      11917,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layerBlob, err := os.ReadFile(filepath.Join("testdata", "fixtures", "vuls-data-raw-test.tar.zst"))
			if err != nil {
				t.Errorf("read %s. err: %v", filepath.Join("testdata", "fixtures", "vuls-data-raw-test.tar.zst"), err)
			}
			layerDesc := generateDescriptor("application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd", layerBlob)
			configBlob := []byte("{}")
			configDesc := generateDescriptor(ocispec.MediaTypeEmptyJSON, configBlob)
			manifestBlob, err := generateManifestContent(configDesc, layerDesc)
			if err != nil {
				t.Errorf("generate a image manifest. err: %v", err)
			}
			manifestDesc := generateDescriptor(ocispec.MediaTypeImageManifest, manifestBlob)

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v2/vuls-data-db/tags/list" && r.Method == "GET":
					if err := json.NewEncoder(w).Encode(struct {
						Tags []string `json:"tags"`
					}{
						Tags: []string{"vuls-data-raw-test"},
					}); err != nil {
						t.Errorf("encode json. err: %v", err)
					}
				case strings.Contains(r.URL.Path, "/manifests/") && (r.Method == "HEAD" || r.Method == "GET"):
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Docker-Content-Digest", string(manifestDesc.Digest))
					w.Header().Set("Content-Length", strconv.Itoa(len([]byte(manifestBlob))))
					if _, err := w.Write([]byte(manifestBlob)); err != nil {
						t.Errorf("write manifest. err: %v", err)
					}
				case strings.Contains(r.URL.Path, "/blobs/") && (r.Method == "HEAD" || r.Method == "GET"):
					ss := strings.Split(r.URL.Path, "/")
					digest := ss[len(ss)-1]
					var desc ocispec.Descriptor
					var content []byte
					switch digest {
					case layerDesc.Digest.String():
						desc = layerDesc
						content = layerBlob
					case configDesc.Digest.String():
						desc = configDesc
						content = configBlob
					case manifestDesc.Digest.String():
						desc = manifestDesc
						content = manifestBlob
					}
					w.Header().Set("Content-Type", desc.MediaType)
					w.Header().Set("Docker-Content-Digest", digest)
					w.Header().Set("Content-Length", strconv.Itoa(len([]byte(content))))
					if _, err := w.Write([]byte(content)); err != nil {
						t.Errorf("write blob. err: %v", err)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			u, err := url.Parse(ts.URL)
			if err != nil {
				t.Errorf("parse url. err: %v", err)
			}

			http.DefaultTransport = ts.Client().Transport

			got, err := status.Status(strings.Replace(tt.args.repository, "ghcr.io/vulsio", u.Host, 1))
			if (err != nil) != tt.wantErr {
				t.Errorf("Status() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got.Repository = tt.args.repository

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Status() = %v, want %v", got, tt.want)
			}
		})
	}
}
