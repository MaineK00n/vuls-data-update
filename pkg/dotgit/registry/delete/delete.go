package delete

import (
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	utilGitHub "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

const githubAPIURL = "https://api.github.com"

type options struct {
	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
}

func Delete(image, token string, opts ...Option) error {
	options := &options{}

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
		owner, pack, ok := strings.Cut(repo.Reference.Repository, "/")
		if !ok {
			return errors.Errorf("unexpected repository format. expected: %q, actual: %q", "<registry>/<owner>/<package>", image)
		}

		var repoType string
		if err := utilGitHub.Do(options.httpClient, http.MethodGet, fmt.Sprintf("%s/users/%s", githubAPIURL, owner), token, func(resp *http.Response) error {
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

		rs, err := ls.List([]ls.Repository{{Type: repoType, Registry: repo.Reference.Registry, Owner: owner, Package: pack}}, token, ls.WithHTTPClient(options.httpClient))
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

		u, err := url.Parse(githubAPIURL)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		switch repoType {
		case "orgs", "users":
			for _, id := range ids {
				uu := u.JoinPath(repoType, owner, "packages", "container", pack, "versions", fmt.Sprintf("%d", id))
				if err := utilGitHub.Do(options.httpClient, http.MethodDelete, uu.String(), token, func(resp *http.Response) error {
					switch resp.StatusCode {
					case http.StatusNoContent:
						slog.Info("Deleted", slog.String("repository", repo.Reference.Repository), slog.String("reference", repo.Reference.Reference), slog.Int("id", id))
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
			return errors.Errorf("unexpected registry type. expected: %q, actual: %q", []string{"orgs", "users"}, repoType)
		}
	default:
		return errors.Errorf("unexpected registry. expected: %q, actual: %q", []string{"ghcr.io"}, repo.Reference.Registry)
	}
}
