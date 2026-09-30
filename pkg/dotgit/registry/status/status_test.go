package status_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/push"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/status"
)

func TestStatus(t *testing.T) {
	type args struct {
		repository string
	}
	tests := []struct {
		name    string
		args    args
		want    ocispec.Manifest
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:6d7d8bb5bf7c01b007c53a0e44625f69c6ee121c87a92cdabd35cdcb99b3fa2f",
						Size:        11917,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-test.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-03T16:21:59Z"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(registry.New())
			defer ts.Close()

			originalTransport := http.DefaultTransport
			http.DefaultTransport = ts.Client().Transport
			defer func() {
				http.DefaultTransport = originalTransport
			}()

			u, err := url.Parse(ts.URL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}

			repo, err := remote.NewRepository(tt.args.repository)
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}
			repo.Reference.Registry = u.Host

			if err := setup(repo.Reference.String()); err != nil {
				t.Fatalf("setup(): %v", err)
			}

			got, err := status.Status(repo.Reference.String())
			if (err != nil) != tt.wantErr {
				t.Errorf("Status() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreFields(ocispec.Manifest{}, "Annotations")); diff != "" {
				t.Errorf("manifest mismatch (-got +want):\n%s", diff)
				return
			}
		})
	}
}

// setup puts the image there the way vuls-data-update puts one there, rather
// than assembling an equivalent by hand.
func setup(image string) error {
	if err := push.Push(image, "testdata/fixtures/vuls-data-raw-test.tar.zst", "gho_xxx"); err != nil {
		return errors.Wrapf(err, "push %q", image)
	}

	return nil
}
