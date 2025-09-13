package cp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/cp"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/push"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/status"
)

func TestCopy(t *testing.T) {
	type args struct {
		from  string
		to    string
		token string
		opts  []cp.Option
	}
	tests := []struct {
		name    string
		args    args
		want    ocispec.Manifest
		wantErr bool
	}{
		{
			name: "copy: vuls-data-db:vuls-data-raw-example -> vuls-data-db-backup:vuls-data-raw-example",
			args: args{
				from:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				to:    "ghcr.io/vulsio/vuls-data-db-backup:vuls-data-raw-example",
				token: "token",
				opts:  []cp.Option{cp.WithForce(false)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:8c0170e9f1022dca68475b82496e665cf81e9028f7cccc572f6a5667c18cde10",
						Size:        11458,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-example.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-28T00:00:00Z"},
			},
		},
		{
			name: "tag: vuls-data-db:vuls-data-raw-example -> vuls-data-db:vuls-data-raw-example-copy",
			args: args{
				from:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				to:    "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example-copy",
				token: "token",
				opts:  []cp.Option{cp.WithForce(false)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:8c0170e9f1022dca68475b82496e665cf81e9028f7cccc572f6a5667c18cde10",
						Size:        11458,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-example.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-28T00:00:00Z"},
			},
		},
		{
			name: "image already exists: vuls-data-db:vuls-data-raw-example -> vuls-data-db-backup:vuls-data-raw-test",
			args: args{
				from:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				to:    "ghcr.io/vulsio/vuls-data-db-backup:vuls-data-raw-test",
				token: "token",
				opts:  []cp.Option{cp.WithForce(false)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:6a7bf907559a6fae2ab74cda866462a7ea06c6dd6c94de6cfbdc951373079b1e",
						Size:        11434,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-test.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-28T00:00:00Z"},
			},
			wantErr: true,
		},
		{
			name: "image already exists, but force copy: vuls-data-db:vuls-data-raw-example -> vuls-data-db-backup:vuls-data-raw-test",
			args: args{
				from:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				to:    "ghcr.io/vulsio/vuls-data-db-backup:vuls-data-raw-test",
				token: "token",
				opts:  []cp.Option{cp.WithForce(true)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:8c0170e9f1022dca68475b82496e665cf81e9028f7cccc572f6a5667c18cde10",
						Size:        11458,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-example.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-28T00:00:00Z"},
			},
			wantErr: false,
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
				t.Fatalf("parse url. err: %v", err)
			}

			fr, err := remote.NewRepository(tt.args.from)
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}
			fr.Reference.Registry = u.Host

			tr, err := remote.NewRepository(tt.args.to)
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}
			tr.Reference.Registry = u.Host

			if err := push.Push(fmt.Sprintf("%s/%s:vuls-data-raw-example", fr.Reference.Registry, fr.Reference.Repository), "testdata/fixtures/vuls-data-raw-example.tar.zst", ""); err != nil {
				t.Fatalf("push to %s: %v", fmt.Sprintf("%s/%s:vuls-data-raw-example", fr.Reference.Registry, fr.Reference.Repository), err)
			}
			if err := push.Push(fmt.Sprintf("%s/%s:vuls-data-raw-test", tr.Reference.Registry, tr.Reference.Repository), "testdata/fixtures/vuls-data-raw-test.tar.zst", ""); err != nil {
				t.Fatalf("push to %s: %v", fmt.Sprintf("%s/%s:vuls-data-raw-test", tr.Reference.Registry, tr.Reference.Repository), err)
			}

			err = cp.Copy(fr.Reference.String(), tr.Reference.String(), tt.args.token, tt.args.opts...)
			switch {
			case err != nil && !tt.wantErr:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr:
				t.Error("expected error has not occurred")
			default:
				got, err := status.Status(tr.Reference.String())
				if err != nil {
					t.Fatalf("get status of %s. err: %v", tr.Reference.String(), err)
				}

				if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreFields(ocispec.Manifest{}, "Annotations")); diff != "" {
					t.Errorf("manifest mismatch (-got +want):\n%s", diff)
				}
			}
		})
	}
}
