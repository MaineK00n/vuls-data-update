package untag

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	utilGitHub "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

const (
	registryHost = "ghcr.io"
	githubAPIURL = "https://api.github.com"
)

type options struct {
	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
}

func Untag(imageRef, token string, opts ...Option) error {
	options := &options{}

	for _, o := range opts {
		o.apply(options)
	}

	slog.Info("Untag dotgit", slog.String("image", imageRef))

	ctx := context.TODO()

	repoRef, rest, ok := strings.CutLast(imageRef, ":")
	if !ok {
		return errors.Errorf("unexpected image format. expected: %q, actual: %q", "ghcr.io/<owner>/<package>:tag", imageRef)
	}
	tag, _, _ := strings.Cut(rest, "@")

	ss := strings.SplitN(repoRef, "/", 3)
	if len(ss) != 3 {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", "ghcr.io/<owner>/<package>", repoRef)
	}
	if ss[0] != registryHost {
		return errors.Errorf("only ghcr.io is supported. repository: %s", repoRef)
	}

	var repoType string
	if err := utilGitHub.Do(options.httpClient, http.MethodGet, fmt.Sprintf("%s/users/%s", githubAPIURL, ss[1]), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusOK:
			type users struct {
				Type string `json:"type"`
			}
			var us users
			if err := json.UnmarshalRead(resp.Body, &us); err != nil {
				return errors.Wrap(err, "decode response")
			}
			switch us.Type {
			case "Organization":
				repoType = "orgs"
			case "User":
				repoType = "users"
			default:
				return errors.Errorf("unexpected repository type. expected: %q, actual: %s", []string{"Organization", "User"}, us.Type)
			}
			return nil
		default:
			return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusOK}, resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}

	dummyDesc, err := options.moveTagToDummy(ctx, ss[1], ss[2], tag, token)
	if err != nil {
		return errors.Wrapf(err, "move tag to dummy")
	}

	if err := options.deleteDummy(repoType, ss[1], ss[2], token, dummyDesc); err != nil {
		return errors.Wrapf(err, "delete dummy")
	}

	return nil
}

func (o options) moveTagToDummy(ctx context.Context, owner, pack, tag, token string) (ocispec.Descriptor, error) {
	dst, err := remote.NewRepository(fmt.Sprintf("%s/%s/%s", registryHost, owner, pack))
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "new repository. URL: %s", fmt.Sprintf("%s/%s/%s", registryHost, owner, pack))
	}

	dst.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(dst.Reference.Host(), auth.Credential{
			Username: "user", // Any string but empty
			Password: token,
		}),
	}

	original, r, err := oras.Fetch(ctx, dst, tag, oras.DefaultFetchOptions)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "fetch original manifest. tag: %s", tag)
	}
	defer r.Close()
	slog.Info("Original digest", slog.String("digest", original.Digest.String()))
	slog.Info("If you made a mistake, run the following command", slog.String("cmd", fmt.Sprintf("vuls-data-update dotgit remote tag ghcr.io/%s/%s@%s %s --token $(gh auth token)", owner, pack, original.Digest.String(), tag)))

	dummyDesc, err := oras.PackManifest(ctx, dst, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls-data-db.dotgit.dummy.artifact.v1", oras.PackManifestOptions{})
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "pack manifest")
	}

	if err := dst.Tag(ctx, dummyDesc, tag); err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "tag. manifest: %s", dummyDesc.Digest.String())
	}

	return dummyDesc, nil
}

func (o options) deleteDummy(repoType, owner, pack, token string, dummyDesc ocispec.Descriptor) error {
	rs, err := ls.List([]ls.Repository{{Type: repoType, Registry: registryHost, Owner: owner, Package: pack}}, token, ls.WithHTTPClient(o.httpClient))
	if err != nil {
		return errors.Wrapf(err, "list versions")
	}

	i := slices.IndexFunc(rs, func(r ls.Response) bool {
		return r.Digest == dummyDesc.Digest.String()
	})
	if i == -1 {
		return errors.Errorf("dummy version not found. digest: %s", dummyDesc.Digest.String())
	}

	if err := utilGitHub.Do(o.httpClient, http.MethodDelete, fmt.Sprintf("%s/%s/%s/packages/container/%s/versions/%d", githubAPIURL, repoType, owner, pack, rs[i].ID), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusNoContent:
			return nil
		default:
			return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusNoContent}, resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}

	return nil
}
