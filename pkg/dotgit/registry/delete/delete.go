package delete

import (
	"encoding/json/v2"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	utilGitHub "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

const githubAPIURL = "https://api.github.com"

type options struct {
	force bool

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
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

// Delete deletes the versions that images name by digest.
//
// The versions of a package are listed once for all of its images, so that
// deleting many, as a sweep of untagged versions does, costs two requests per
// version on top of one listing, rather than a listing per version. A listing
// pages through every version of the package, and taking one per version is
// what ran the sweeps into GitHub's rate limits.
//
// An image that fails to be deleted does not stop the others, nor does a
// package whose owner or versions cannot be read, which fails its own images.
// Delete goes on with the rest, logs each failure as it happens, and returns
// the errors of all that failed.
func Delete(images []string, token string, opts ...Option) error {
	options := &options{
		force: false,
	}

	for _, o := range opts {
		o.apply(options)
	}

	type target struct {
		image  string
		digest string
	}
	var (
		packages []string
		targets  = make(map[string][]target)
	)
	for _, image := range images {
		repo, err := remote.NewRepository(image)
		if err != nil {
			return errors.Wrapf(err, "create client for %s", image)
		}
		if repo.Reference.Reference == "" {
			return errors.Errorf("unexpected image format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>@<digest>"}, image)
		}
		if repo.Reference.Registry != "ghcr.io" {
			return errors.Errorf("unexpected registry. expected: %q, actual: %q", []string{"ghcr.io"}, repo.Reference.Registry)
		}
		if !strings.Contains(repo.Reference.Repository, "/") {
			return errors.Errorf("unexpected repository format. expected: %q, actual: %q", "<registry>/<owner>/<package>", image)
		}

		if _, ok := targets[repo.Reference.Repository]; !ok {
			packages = append(packages, repo.Reference.Repository)
		}
		targets[repo.Reference.Repository] = append(targets[repo.Reference.Repository], target{image: image, digest: repo.Reference.Reference})
	}

	// The type of an owner is looked up once, a failed lookup included, which
	// fails every package of the owner without asking again.
	type lookup struct {
		repoType string
		err      error
	}
	owners := make(map[string]lookup)

	var (
		errs   []error
		failed int
	)
	for _, p := range packages {
		owner, pack, _ := strings.Cut(p, "/")

		o, ok := owners[owner]
		if !ok {
			o.repoType, o.err = ownerType(options.httpClient, owner, token)
			owners[owner] = o
		}
		if o.err != nil {
			err := errors.Wrapf(o.err, "delete the images of %s. get the type of %s", p, owner)
			slog.Warn("Failed to delete the images of a package, go on with the rest", slog.String("repository", p), slog.Int("images", len(targets[p])), slog.Any("error", err))
			errs = append(errs, err)
			failed += len(targets[p])
			continue
		}
		repoType := o.repoType

		rs, err := ls.List([]ls.Repository{{Type: repoType, Registry: "ghcr.io", Owner: owner, Package: pack}}, token, ls.WithHTTPClient(options.httpClient))
		if err != nil {
			err = errors.Wrapf(err, "delete the images of %s. list versions", p)
			slog.Warn("Failed to delete the images of a package, go on with the rest", slog.String("repository", p), slog.Int("images", len(targets[p])), slog.Any("error", err))
			errs = append(errs, err)
			failed += len(targets[p])
			continue
		}

		// ls reports a version once per tag, and once with an empty name when
		// it has none, so a digest can match several rows of the same version,
		// and every row of a version carries the same id.
		ids := make(map[string][]int)
		for _, r := range rs {
			if !slices.Contains(ids[r.Digest], r.ID) {
				ids[r.Digest] = append(ids[r.Digest], r.ID)
			}
		}

		for _, t := range targets[p] {
			if err := func() error {
				if len(ids[t.digest]) == 0 {
					return errors.Errorf("no matching digest: %q found in %s", t.digest, p)
				}
				for _, id := range ids[t.digest] {
					if err := deleteVersion(options.httpClient, repoType, owner, pack, id, t.digest, token, options.force); err != nil {
						return errors.Wrapf(err, "delete version %d", id)
					}
				}
				return nil
			}(); err != nil {
				err = errors.Wrapf(err, "delete %s", t.image)
				slog.Warn("Failed to delete an image, go on with the rest", slog.String("image", t.image), slog.Any("error", err))
				errs = append(errs, err)
				failed++
			}
		}
	}

	if len(errs) > 0 {
		return errors.Wrapf(stderrors.Join(errs...), "delete images. failed: %d of %d", failed, len(images))
	}
	return nil
}

func ownerType(client *http.Client, owner, token string) (string, error) {
	var repoType string
	if err := utilGitHub.Do(client, http.MethodGet, fmt.Sprintf("%s/users/%s", githubAPIURL, owner), token, func(resp *http.Response) error {
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
		return "", errors.Wrap(err, "call GitHub API")
	}
	return repoType, nil
}

// deleteVersion deletes the version id of the package, unless it carries a
// tag and force is not set.
//
// The listing a caller sweeping untagged versions based its decision on is a
// snapshot, and so is the listing Delete found the id in, taken before the
// versions ahead of this one were deleted. A version that was untagged in them
// may carry a tag by now. Deleting it takes the tag with it and nothing puts it
// back. GHCR has no conditional delete, so the tags are read from the version
// itself right before the delete, which is as close to the delete as they can
// be read.
//
// A version that is gone by then, deleted by someone else between the listing
// and here, is what deleting it is for, and is skipped.
func deleteVersion(client *http.Client, repoType, owner, pack string, id int, digest, token string, force bool) error {
	u, err := url.Parse(githubAPIURL)
	if err != nil {
		return errors.Wrap(err, "parse url")
	}
	switch repoType {
	case "orgs", "users":
		u = u.JoinPath(repoType, owner, "packages", "container", pack, "versions", fmt.Sprintf("%d", id))
	default:
		return errors.Errorf("unexpected registry type. expected: %q, actual: %q", []string{"orgs", "users"}, repoType)
	}

	repository := fmt.Sprintf("%s/%s", owner, pack)

	v, err := getVersion(client, u.String(), token)
	if err != nil {
		return errors.Wrap(err, "get version")
	}
	if v == nil {
		slog.Warn("Skip a version that is already deleted", slog.String("repository", repository), slog.String("reference", digest), slog.Int("id", id))
		return nil
	}
	if v.Metadata == nil || v.Metadata.Container == nil {
		return errors.Errorf("missing container metadata for response: %+v", *v)
	}
	if v.Name != digest {
		return errors.Errorf("unexpected version digest. expected: %q, actual: %q", digest, v.Name)
	}
	if len(v.Metadata.Container.Tags) > 0 {
		tags := make([]string, 0, len(v.Metadata.Container.Tags))
		for _, t := range v.Metadata.Container.Tags {
			tags = append(tags, fmt.Sprintf("ghcr.io/%s:%s", repository, t))
		}
		if !force {
			return errors.Errorf("refuse to delete a tagged version. digest: %q, tags: %q", digest, tags)
		}
		slog.Warn("Deleting a tagged version", slog.String("repository", repository), slog.String("reference", digest), slog.Any("tags", tags))
	}

	found := true
	if err := utilGitHub.Do(client, http.MethodDelete, u.String(), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusNoContent:
			return nil
		case http.StatusNotFound:
			found = false
			return nil
		default:
			return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusNoContent, http.StatusNotFound}, resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}
	if found {
		slog.Info("Deleted", slog.String("repository", repository), slog.String("reference", digest), slog.Int("id", id))
		return nil
	}

	// 404 is the answer for a version that went between the read above and
	// here, or by an attempt of this delete that the API client retried after
	// it went through. GitHub also answers 404 for what a token may read but
	// not act on, so the version is read again, and only a version that is no
	// longer there counts as deleted.
	v, err = getVersion(client, u.String(), token)
	if err != nil {
		return errors.Wrap(err, "get version after the delete answered 404")
	}
	if v != nil {
		return errors.Errorf("the delete answered 404, yet the version is still there. digest: %q, id: %d", digest, id)
	}
	slog.Warn("Skip a version that is already deleted", slog.String("repository", repository), slog.String("reference", digest), slog.Int("id", id))
	return nil
}

// getVersion reads the version at apiurl, or returns nil when there is none.
func getVersion(client *http.Client, apiurl, token string) (*ls.Version, error) {
	var v *ls.Version
	if err := utilGitHub.Do(client, http.MethodGet, apiurl, token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusOK:
			v = new(ls.Version)
			if err := json.UnmarshalRead(resp.Body, v); err != nil {
				return errors.Wrap(err, "decode response")
			}
			return nil
		case http.StatusNotFound:
			return nil
		default:
			return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		}
	}); err != nil {
		return nil, errors.Wrap(err, "call GitHub API")
	}
	return v, nil
}
