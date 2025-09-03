package tag

import (
	"context"
	"log"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

func Tag(imageRef, newTag, token string) error {
	log.Printf("[INFO] Tag dotgit %s as %s", imageRef, newTag)

	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", imageRef)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected image format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, imageRef)
	}

	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Host(), auth.Credential{
			Username: "user", // Any string but empty
			Password: token,
		}),
	}

	if _, err := oras.Tag(context.TODO(), repo, repo.Reference.Reference, newTag); err != nil {
		return errors.Wrapf(err, "tag %s as %s", repo.Reference.Reference, newTag)
	}

	return nil
}
