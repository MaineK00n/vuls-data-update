package remote

import (
	"context"
	"encoding/json"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

type RepoStatus struct {
	Repository string             `json:"repository"`
	Layer      ocispec.Descriptor `json:"layer"`
}

func Status(repository string) (RepoStatus, error) {
	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return RepoStatus{}, errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference == "" {
		return RepoStatus{}, errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, repository)
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return RepoStatus{}, errors.Wrap(err, "fetch manifest")
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return RepoStatus{}, errors.Wrap(err, "decode manifest")
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return RepoStatus{}, errors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	return RepoStatus{
		Repository: repository,
		Layer:      *l,
	}, nil
}
