package push_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/push"
)

func TestPush(t *testing.T) {
	type args struct {
		image  string
		dotgit string
		token  string
		opts   []push.Option
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
				image:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				token:  "gho_xxx",
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:fad1a1a5fa3fc82cb3d7586818ec5dcb8810c41bbd9c7373cd9d932d8f9f3c0f",
						Size:        11403,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-test.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-03T16:21:59Z"},
			},
		},
		{
			name: "tag already exists",
			args: args{
				image:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				token:  "gho_xxx",
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:07c46f81ad565af6452da17ab2c09220e2220855fb34306255549c6063d8fbaa",
						Size:        10392,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-example.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-03T16:21:59Z"},
			},
			wantErr: true,
		},
		{
			// Rejected before anything is pushed, so the tag keeps the manifest
			// setup gave it. A file store would otherwise tar the directory up
			// and push it under the dotgit layer media type.
			name: "dotgit is a directory",
			args: args{
				image:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				dotgit: "testdata/fixtures",
				token:  "gho_xxx",
				opts:   []push.Option{push.WithForce(true)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:07c46f81ad565af6452da17ab2c09220e2220855fb34306255549c6063d8fbaa",
						Size:        10392,
						Annotations: map[string]string{ocispec.AnnotationTitle: "vuls-data-raw-example.tar.zst"},
					},
				},
				Annotations: map[string]string{"org.opencontainers.image.created": "2025-09-03T16:21:59Z"},
			},
			wantErr: true,
		},
		{
			name: "tag already exists, but force push",
			args: args{
				image:  "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-example",
				dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				token:  "gho_xxx",
				opts:   []push.Option{push.WithForce(true)},
			},
			want: ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls-data-db.dotgit+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{
					{
						MediaType:   "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd",
						Digest:      "sha256:fad1a1a5fa3fc82cb3d7586818ec5dcb8810c41bbd9c7373cd9d932d8f9f3c0f",
						Size:        11403,
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

			repo, err := remote.NewRepository(tt.args.image)
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}
			repo.Reference.Registry = u.Host

			if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
				t.Fatalf("setup(): %v", err)
			}

			if err := push.Push(repo.Reference.String(), tt.args.dotgit, tt.args.token, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Push() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := check(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository), repo.Reference.Reference, tt.want); err != nil {
				t.Errorf("check(): %v", err)
			}
		})
	}
}

// TestPushManifestUnderTag pins how the manifest reaches the registry, which
// TestPush cannot see: a manifest PUT under its digest creates a version that
// stays untagged until the tag PUT that follows lands, and a cleanup listing
// the package in that window deletes a version that is about to be tagged.
// Either way the tag ends up resolving to the same manifest.
func TestPushManifestUnderTag(t *testing.T) {
	const tag = "vuls-data-raw-test"

	var (
		mu              sync.Mutex
		manifestPutRefs []string
	)
	h := registry.New()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ref, ok := strings.Cut(r.URL.Path, "/manifests/"); ok && r.Method == http.MethodPut {
			mu.Lock()
			manifestPutRefs = append(manifestPutRefs, ref)
			mu.Unlock()
		}
		h.ServeHTTP(w, r)
	}))
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

	repo, err := remote.NewRepository(fmt.Sprintf("ghcr.io/vulsio/vuls-data-db:%s", tag))
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	repo.Reference.Registry = u.Host

	if err := push.Push(repo.Reference.String(), "testdata/fixtures/vuls-data-raw-test.tar.zst", "gho_xxx"); err != nil {
		t.Fatalf("Push(): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if diff := cmp.Diff(manifestPutRefs, []string{tag}); diff != "" {
		t.Errorf("Push() manifest PUT references (-got +want):\n%s", diff)
	}
}

// TestPushNonTagReference covers what the manifest would otherwise be PUT
// under. remote.NewRepository takes a digest-qualified image too and puts the
// digest in Reference, which Copy would then push under, so a reference that
// is not a tag has to be turned away before anything reaches the registry.
func TestPushNonTagReference(t *testing.T) {
	const digest = "sha256:fad1a1a5fa3fc82cb3d7586818ec5dcb8810c41bbd9c7373cd9d932d8f9f3c0f"

	var (
		mu       sync.Mutex
		requests int
	)
	h := registry.New()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
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

	for _, image := range []string{
		fmt.Sprintf("%s/vulsio/vuls-data-db", u.Host),
		fmt.Sprintf("%s/vulsio/vuls-data-db@%s", u.Host, digest),
		fmt.Sprintf("%s/vulsio/vuls-data-db:vuls-data-raw-test@%s", u.Host, digest),
	} {
		if err := push.Push(image, "testdata/fixtures/vuls-data-raw-test.tar.zst", "gho_xxx"); err == nil {
			t.Errorf("Push(%q) error = nil, want an error", image)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if requests != 0 {
		t.Errorf("Push() made %d requests, want none before the reference is rejected", requests)
	}
}

func setup(repository string) error {
	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, repository)
	}

	// Assembled and copied the way Push does it, so that the tag the tests find
	// already there was never a version without one.
	store, err := file.New("testdata/fixtures")
	if err != nil {
		return errors.Wrapf(err, "create file store in %q", "testdata/fixtures")
	}
	defer store.Close()

	layerDescriptor, err := store.Add(ctx, "vuls-data-raw-example.tar.zst", "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd", "")
	if err != nil {
		return errors.Wrap(err, "add dotgit layer")
	}

	desc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls-data-db.dotgit+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
	if err != nil {
		return errors.Wrap(err, "pack manifest")
	}

	if err := store.Tag(ctx, desc, "vuls-data-raw-example"); err != nil {
		return errors.Wrapf(err, "tag %+v in store", desc)
	}

	if _, err := oras.Copy(ctx, store, "vuls-data-raw-example", repo, "vuls-data-raw-example", oras.DefaultCopyOptions); err != nil {
		return errors.Wrapf(err, "copy to %q", repository)
	}

	return nil
}

func check(repository, tag string, want ocispec.Manifest) error {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, repository)
	}

	_, fetchedManifestContent, err := oras.FetchBytes(context.TODO(), repo, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return errors.Wrapf(err, "fetch manifest for %s", tag)
	}

	var got ocispec.Manifest
	if err := json.Unmarshal(fetchedManifestContent, &got); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	if diff := cmp.Diff(got, want, cmpopts.IgnoreFields(ocispec.Manifest{}, "Annotations")); diff != "" {
		return errors.Errorf("manifest mismatch (-got +want):\n%s", diff)
	}

	return nil
}
