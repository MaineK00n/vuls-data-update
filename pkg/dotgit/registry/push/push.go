package push

import (
	"context"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type options struct {
	force bool
}

type Option interface {
	apply(*options)
}

type forceOption bool

func (f forceOption) apply(opts *options) {
	opts.force = bool(f)
}

func WithForce(force bool) Option {
	return forceOption(force)
}

func Push(image, dotgit, token string, opts ...Option) error {
	options := &options{
		force: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	ctx := context.TODO()

	repo, err := remote.NewRepository(image)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", image)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>:<tag>"}, image)
	}

	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Host(), auth.Credential{
			Username: "user", // Any string but empty
			Password: token,
		}),
	}

	if !options.force {
		_, err := repo.Resolve(ctx, repo.Reference.Reference)
		if err == nil {
			return errors.Errorf("tag %q already exists in %q", repo.Reference.Reference, repo.Reference.Repository)
		}
		if !errors.Is(err, errdef.ErrNotFound) {
			return errors.Wrap(err, "check existing tags")
		}
	}

	bs, err := os.ReadFile(dotgit)
	if err != nil {
		return errors.Wrapf(err, "read %q", dotgit)
	}

	layerDescriptor, err := oras.PushBytes(ctx, repo, "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd", []byte(bs))
	if err != nil {
		return errors.Wrap(err, "push dotgit layer")
	}
	if layerDescriptor.Annotations == nil {
		layerDescriptor.Annotations = make(map[string]string)
	}
	if _, ok := layerDescriptor.Annotations[ocispec.AnnotationTitle]; !ok {
		layerDescriptor.Annotations[ocispec.AnnotationTitle] = filepath.Base(dotgit)
	}

	desc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls-data-db.dotgit+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
	if err != nil {
		return errors.Wrap(err, "pack manifest")
	}

	if err := repo.Tag(ctx, desc, repo.Reference.Reference); err != nil {
		return errors.Wrapf(err, "tagged for %+v", desc)
	}

	return nil
}
