package pull_test

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
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

func TestPull(t *testing.T) {
	type args struct {
		tag     string
		restore bool
	}
	tests := []struct {
		name      string
		args      args
		layerBlob string
		golden    string
		hasError  bool
	}{
		{
			name: "vuls-data-raw-test restore: false",
			args: args{
				tag: "vuls-data-raw-test",
			},
			layerBlob: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			golden:    "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test restore: true",
			args: args{
				tag:     "vuls-data-raw-test",
				restore: true,
			},
			layerBlob: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			golden:    "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			name: "vuls-data-raw-test-archive-1 restore: false",
			args: args{
				tag:     "vuls-data-raw-test-archive-1",
				restore: false,
			},
			layerBlob: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			golden:    "testdata/golden/vuls-data-raw-test-archive-1.tar.zst",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layerBlob, err := os.ReadFile(tt.layerBlob)
			if err != nil {
				t.Errorf("read %s. err: %v", tt.layerBlob, err)
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
						Tags: []string{tt.args.tag},
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

			dir := t.TempDir()
			err = pull.Pull(fmt.Sprintf("%s/vuls-data-db:%s", u.Host, tt.args.tag), pull.WithDir(dir), pull.WithRestore(tt.args.restore))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				var got []string
				if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}

					p, err := filepath.Rel(dir, path)
					if err != nil {
						return err
					}

					if p == "." {
						return nil
					}

					got = append(got, p)

					return nil
				}); err != nil {
					t.Errorf("walk dir. err: %v", err)
				}

				var want []string
				f, err := os.Open(tt.golden)
				if err != nil {
					t.Errorf("open %s. err: %v", tt.golden, err)
				}
				defer f.Close()

				r, err := zstd.NewReader(f)
				if err != nil {
					t.Errorf("new zstd reader. err: %v", err)
				}
				defer r.Close()

				tr := tar.NewReader(r)
				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("next tar reader. err: %v", err)
					}
					want = append(want, filepath.Clean(hdr.Name))
				}

				if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(i, j string) bool {
					return i < j
				})); diff != "" {
					t.Errorf("Pull(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
