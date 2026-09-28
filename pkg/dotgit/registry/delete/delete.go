package delete

import (
	"encoding/json/v2"
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

type options struct {
	apiEndpoint APIEndpoint
	force       bool
}

type Option interface {
	apply(*options)
}

type apiOption struct {
	APIEndpoint APIEndpoint
}

type APIEndpoint struct {
	GitHub *GitHub
}

type GitHub struct {
	BaseURL string
	Type    string
}

func (a apiOption) apply(opts *options) {
	opts.apiEndpoint = a.APIEndpoint
}

func WithAPIEndpoint(a APIEndpoint) Option {
	return apiOption{APIEndpoint: a}
}

type forceOption bool

func (f forceOption) apply(opts *options) {
	opts.force = bool(f)
}

func WithForce(force bool) Option {
	return forceOption(force)
}

func Delete(image, token string, opts ...Option) error {
	options := &options{
		apiEndpoint: APIEndpoint{
			GitHub: func() *GitHub {
				if !strings.HasPrefix(image, "ghcr.io") {
					return nil
				}
				return &GitHub{BaseURL: "https://api.github.com"}
			}(),
		},
		force: false,
	}

	for _, o := range opts {
		o.apply(options)
	}

	repo, err := remote.NewRepository(image)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", image)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected image format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>@<digest>"}, image)
	}

	switch repo.Reference.Registry {
	case "ghcr.io":
		owner, pack, err := func() (string, string, error) {
			switch repo.Reference.Registry {
			case "ghcr.io":
				lhs, rhs, ok := strings.Cut(repo.Reference.Repository, "/")
				if !ok {
					return "", "", errors.Errorf("unexpected repository format. expected: %q, actual: %q", "<registry>/<owner>/<package>", image)
				}
				return lhs, rhs, nil
			default:
				return "", "", nil
			}
		}()
		if err != nil {
			return errors.Wrap(err, "parse repository")
		}

		if options.apiEndpoint.GitHub == nil {
			return errors.Errorf("GitHub API configuration is required for registry %q", repo.Reference.Registry)
		}

		if options.apiEndpoint.GitHub.Type == "" {
			if err := utilGitHub.Do(http.MethodGet, fmt.Sprintf("%s/users/%s", options.apiEndpoint.GitHub.BaseURL, owner), token, func(resp *http.Response) error {
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
						options.apiEndpoint.GitHub.Type = "orgs"
					case "User":
						options.apiEndpoint.GitHub.Type = "users"
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
		}

		rs, err := ls.List([]ls.Repository{{Type: options.apiEndpoint.GitHub.Type, Registry: repo.Reference.Registry, Owner: owner, Package: pack}}, token, ls.WithbaseURL(options.apiEndpoint.GitHub.BaseURL))
		if err != nil {
			return errors.Wrap(err, "list versions")
		}

		// ls reports a version once per tag, and once with an empty name when
		// it has none, so a digest can match several rows of the same version.
		matched := make([]ls.Response, 0, len(rs))
		for _, r := range rs {
			if r.Digest == repo.Reference.Reference {
				matched = append(matched, r)
			}
		}
		if len(matched) == 0 {
			return errors.Errorf("no matching digest: %q found in %s", repo.Reference.Reference, repo.Reference.Repository)
		}

		tags := make([]string, 0, len(matched))
		for _, r := range matched {
			if r.Name != "" {
				tags = append(tags, r.Name)
			}
		}
		// The listing a caller sweeping untagged versions based its decision on
		// is a snapshot, and a version that was untagged when it was taken may
		// carry a tag by the time its turn comes. Deleting it takes the tag
		// with it and nothing puts it back. GHCR has no conditional delete, so
		// the listing above, taken immediately before the delete, is as close
		// to the delete as the tags can be read.
		if len(tags) > 0 {
			if !options.force {
				return errors.Errorf("refuse to delete a tagged version. digest: %q, tags: %q", repo.Reference.Reference, tags)
			}
			slog.Warn("Deleting a tagged version", slog.String("repository", repo.Reference.Repository), slog.String("reference", repo.Reference.Reference), slog.Any("tags", tags))
		}

		u, err := url.Parse(options.apiEndpoint.GitHub.BaseURL)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		switch options.apiEndpoint.GitHub.Type {
		case "orgs", "users":
			// Every row of a version carries the same id, and GHCR answers 404
			// to the second delete of one.
			var deleted []int
			for _, r := range matched {
				if slices.Contains(deleted, r.ID) {
					continue
				}

				uu := u.JoinPath(options.apiEndpoint.GitHub.Type, owner, "packages", "container", pack, "versions", fmt.Sprintf("%d", r.ID))
				if err := utilGitHub.Do(http.MethodDelete, uu.String(), token, func(resp *http.Response) error {
					switch resp.StatusCode {
					case http.StatusNoContent:
						slog.Info("Deleted", slog.String("repository", repo.Reference.Repository), slog.String("reference", repo.Reference.Reference), slog.Int("id", r.ID))
						return nil
					default:
						return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusNoContent}, resp.StatusCode)
					}
				}); err != nil {
					return errors.Wrap(err, "call GitHub API")
				}

				deleted = append(deleted, r.ID)
			}

			return nil
		default:
			return errors.Errorf("unexpected registry type. expected: %q, actual: %q", []string{"orgs", "users"}, options.apiEndpoint.GitHub.Type)
		}
	default:
		return errors.Errorf("unexpected registry. expected: %q, actual: %q", []string{"ghcr.io"}, repo.Reference.Registry)
	}
}
