package status

import (
	"context"
	"encoding/json/v2"
	"slices"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func Status(repository string) (ocispec.Manifest, error) {
	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return ocispec.Manifest{}, errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference == "" {
		return ocispec.Manifest{}, errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, repository)
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return ocispec.Manifest{}, errors.Wrap(err, "fetch manifest")
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.UnmarshalRead(r, &manifest); err != nil {
		return ocispec.Manifest{}, errors.Wrap(err, "decode manifest")
	}

	if !slices.ContainsFunc(manifest.Layers, func(l ocispec.Descriptor) bool {
		return l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd"
	}) {
		return ocispec.Manifest{}, errors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	return manifest, nil
}
