package delete

import (
	"encoding/json/v2"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	utilGitHub "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

type options struct {
	apiEndpoint APIEndpoint
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

		var ids []int
		for _, r := range rs {
			if r.Digest == repo.Reference.Reference {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) == 0 {
			return errors.Errorf("no matching digest: %q found in %s", repo.Reference.Reference, repo.Reference.Repository)
		}

		u, err := url.Parse(options.apiEndpoint.GitHub.BaseURL)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		switch options.apiEndpoint.GitHub.Type {
		case "orgs", "users":
			for _, id := range ids {
				uu := u.JoinPath(options.apiEndpoint.GitHub.Type, owner, "packages", "container", pack, "versions", fmt.Sprintf("%d", id))
				if err := utilGitHub.Do(http.MethodDelete, uu.String(), token, func(resp *http.Response) error {
					switch resp.StatusCode {
					case http.StatusNoContent:
						log.Printf("[INFO] Deleted: %s@%s (ID: %d)\n", repo.Reference.Repository, repo.Reference.Reference, id)
						return nil
					default:
						return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusNoContent}, resp.StatusCode)
					}
				}); err != nil {
					return errors.Wrap(err, "call GitHub API")
				}
			}

			return nil
		default:
			return errors.Errorf("unexpected registry type. expected: %q, actual: %q", []string{"orgs", "users"}, options.apiEndpoint.GitHub.Type)
		}
	default:
		return errors.Errorf("unexpected registry. expected: %q, actual: %q", []string{"ghcr.io"}, repo.Reference.Registry)
	}
}
