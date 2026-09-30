package push

import (
	"context"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
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
	// Reference is whatever followed the repository, a digest included, and it
	// is what the manifest is PUT under below. Only a tag will do.
	if err := repo.Reference.ValidateReferenceAsTag(); err != nil {
		return errors.Wrapf(err, "unexpected repository format. expected: %q, actual: %q", []string{"<repository>:<tag>"}, image)
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

	// The store would happily tar a directory up and hand it back under the
	// layer media type below, which is not what that media type means.
	fi, err := os.Stat(dotgit)
	if err != nil {
		return errors.Wrapf(err, "stat %q", dotgit)
	}
	if fi.IsDir() {
		return errors.Errorf("dotgit must be a file, but %q is a directory", dotgit)
	}

	// Assemble the artifact locally, then copy it. oras.Copy PUTs the manifest
	// under the tag, so the version exists tagged from its first moment.
	// Packing straight into the repository instead PUTs the manifest under its
	// digest and tags it afterwards, and in between the version is untagged: a
	// cleanup that lists the package in that window sees a version it believes
	// is garbage and deletes it once it has been tagged.
	store, err := file.New(filepath.Dir(dotgit))
	if err != nil {
		return errors.Wrapf(err, "create file store in %q", filepath.Dir(dotgit))
	}
	defer store.Close()

	// An empty path resolves to the name under the store's directory, which is
	// where dotgit is. Add streams the file to take its digest and Copy streams
	// it again to push it, so it is never held whole.
	layerDescriptor, err := store.Add(ctx, filepath.Base(dotgit), "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd", "")
	if err != nil {
		return errors.Wrapf(err, "add %q as dotgit layer", dotgit)
	}

	desc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls-data-db.dotgit+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
	if err != nil {
		return errors.Wrap(err, "pack manifest")
	}

	if err := store.Tag(ctx, desc, repo.Reference.Reference); err != nil {
		return errors.Wrapf(err, "tag %+v in store", desc)
	}

	if _, err := oras.Copy(ctx, store, repo.Reference.Reference, repo, repo.Reference.Reference, oras.DefaultCopyOptions); err != nil {
		return errors.Wrapf(err, "copy to %q", image)
	}

	return nil
}
