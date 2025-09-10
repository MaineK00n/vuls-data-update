package ls

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	utilGitHub "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/util/github"
)

const baseURL = "https://api.github.com"

type options struct {
	baseURL    string
	taggedOnly bool
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithbaseURL(url string) Option {
	return baseURLOption(url)
}

type taggedOnlyOption bool

func (t taggedOnlyOption) apply(opts *options) {
	opts.taggedOnly = bool(t)
}

func WithTaggedOnly(taggedOnly bool) Option {
	return taggedOnlyOption(taggedOnly)
}

type Repository struct {
	Type     string `json:"type"`
	Registry string `json:"registry"`
	Owner    string `json:"owner"`
	Package  string `json:"name"`
}

type Version struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	PackageHTMLURL string    `json:"package_html_url"`
	HTMLURL        *string   `json:"html_url,omitempty"`
	License        *string   `json:"license,omitempty"`
	Description    *string   `json:"description,omitempty"`
	CreatedAt      string    `json:"created_at"`
	UpdatedAt      string    `json:"updated_at"`
	DeletedAt      *string   `json:"deleted_at,omitempty"`
	Metadata       *Metadata `json:"metadata,omitempty"`
}

type Metadata struct {
	PackageType string     `json:"package_type"`
	Container   *Container `json:"container,omitempty"`
	Docker      *Docker    `json:"docker,omitempty"`
}

type Container struct {
	Tags []string `json:"tags"`
}

type Docker struct {
	Tags []string `json:"tags"`
}

type Response struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Digest    string  `json:"digest"`
	CreatedAt string  `json:"created_at"`
	URL       string  `json:"url,omitempty"`
	HTMLURL   *string `json:"html_url,omitempty"`
}

func List(repositories []Repository, token string, opts ...Option) ([]Response, error) {
	options := &options{
		baseURL:    baseURL,
		taggedOnly: false,
	}

	for _, o := range opts {
		o.apply(options)
	}

	var ps []Response
	for _, repository := range repositories {
		switch repository.Registry {
		case "ghcr.io":
			if repository.Type == "" {
				if err := utilGitHub.Do(http.MethodGet, fmt.Sprintf("%s/users/%s", options.baseURL, repository.Owner), token, func(resp *http.Response) error {
					switch resp.StatusCode {
					case http.StatusOK:
						type users struct {
							Type string `json:"type"`
						}
						var us users
						if err := json.NewDecoder(resp.Body).Decode(&us); err != nil {
							return errors.Wrap(err, "decode response")
						}
						switch us.Type {
						case "Organization":
							repository.Type = "orgs"
						case "User":
							repository.Type = "users"
						default:
							return errors.Errorf("unexpected repository type. expected: %q, actual: %s", []string{"Organization", "User"}, us.Type)
						}
						return nil
					default:
						return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusOK}, resp.StatusCode)
					}
				}); err != nil {
					return nil, errors.Wrap(err, "call GitHub API")
				}
			}

			u, err := url.Parse(options.baseURL)
			if err != nil {
				return nil, errors.Wrap(err, "parse url")
			}
			switch repository.Type {
			case "orgs", "users":
				u = u.JoinPath(repository.Type, repository.Owner, "packages", "container", repository.Package, "versions")
			default:
				return nil, errors.Errorf("unexpected registry type. expected: %q, actual: %q", []string{"orgs", "users"}, repository.Type)
			}

			for page := 1; ; page++ {
				q := u.Query()
				q.Set("page", fmt.Sprintf("%d", page))
				q.Set("per_page", "100")
				u.RawQuery = q.Encode()

				isLastPage := false
				if err := utilGitHub.Do(http.MethodGet, u.String(), token, func(resp *http.Response) error {
					switch resp.StatusCode {
					case http.StatusOK:
						var vs []Version
						if err := json.NewDecoder(resp.Body).Decode(&vs); err != nil {
							return errors.Wrap(err, "decode response")
						}

						for _, v := range vs {
							if v.Metadata == nil {
								return errors.Errorf("missing metadata for response: %+v", v)
							}
							switch v.Metadata.PackageType {
							case "container":
								if v.Metadata.Container == nil {
									return errors.Errorf("missing container metadata for response: %+v", v)
								}
								if !options.taggedOnly && len(v.Metadata.Container.Tags) == 0 {
									ps = append(ps, Response{
										ID:        v.ID,
										Name:      "",
										Digest:    v.Name,
										CreatedAt: v.CreatedAt,
										URL:       v.URL,
										HTMLURL:   v.HTMLURL,
									})
								}
								for _, tag := range v.Metadata.Container.Tags {
									ps = append(ps, Response{
										ID:        v.ID,
										Name:      fmt.Sprintf("ghcr.io/%s/%s:%s", repository.Owner, repository.Package, tag),
										Digest:    v.Name,
										CreatedAt: v.CreatedAt,
										URL:       v.URL,
										HTMLURL:   v.HTMLURL,
									})
								}
							default:
								return errors.Errorf("unexpected package type. expected: %q, actual: %q", "container", v.Metadata.PackageType)
							}
						}

						if !strings.Contains(resp.Header.Get("Link"), "rel=\"next\"") {
							isLastPage = true
						}

						return nil
					default:
						return errors.Errorf("unexpected response status. expected: %d, actual: %d", []int{http.StatusOK}, resp.StatusCode)
					}
				}); err != nil {
					return nil, errors.Wrap(err, "call GitHub API")
				}

				if isLastPage {
					break
				}
			}
		default:
			return nil, errors.Errorf("unexpected registry. expected: %q, actual: %q", []string{"ghcr.io"}, repository.Registry)
		}
	}

	return ps, nil
}
