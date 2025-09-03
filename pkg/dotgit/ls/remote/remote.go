package remote

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const baseURL = "https://api.github.com"

type options struct {
	baseURL string
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
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	CreatedAt string `json:"created_at"`
}

func List(remotes []string, token string, opts ...Option) ([]Response, error) {
	options := &options{
		baseURL: baseURL,
	}

	for _, o := range opts {
		o.apply(options)
	}

	var ps []Response
	for _, remote := range remotes {
		targetType, rhs, ok := strings.Cut(remote, ":")
		if !ok {
			return nil, errors.Errorf("unexpected remote format. expected: %q, actual: %q", "<type: (org|user)>:<name>/<package name>", remote)
		}
		target, name, ok := strings.Cut(rhs, "/")
		if !ok {
			return nil, errors.Errorf("unexpected remote format. expected: %q, actual: %q", "<type: (org|user)>:<name>/<package name>", remote)
		}

		u, err := url.Parse(options.baseURL)
		if err != nil {
			return nil, errors.Wrap(err, "parse url")
		}

		switch targetType {
		case "org":
			u = u.JoinPath("orgs", target, "packages", "container", name, "versions")
		case "user":
			u = u.JoinPath("user", "packages", "container", name, "versions")
		default:
			return nil, errors.Errorf("unexpected remote type. expected: %q, actual: %q", []string{"org", "user"}, targetType)
		}

		header := make(http.Header)
		header.Set("Accept", "application/vnd.github+json")
		header.Set("X-GitHub-Api-Version", "2022-11-28")
		header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		for page := 1; ; page++ {
			q := u.Query()
			q.Set("page", fmt.Sprintf("%d", page))
			q.Set("per_page", "100")
			u.RawQuery = q.Encode()

			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				return nil, errors.Wrap(err, "create request")
			}
			req.Header = header

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, errors.Wrap(err, "do request")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return nil, errors.Errorf("unexpected response status. expected: %d, actual: %d", http.StatusOK, resp.StatusCode)
			}

			var vs []Version
			if err := json.NewDecoder(resp.Body).Decode(&vs); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}

			for _, v := range vs {
				if v.Metadata == nil {
					return nil, errors.Errorf("missing metadata for response: %+v", v)
				}
				switch v.Metadata.PackageType {
				case "container":
					if v.Metadata.Container == nil {
						return nil, errors.Errorf("missing container metadata for response: %+v", v)
					}
					for _, tag := range v.Metadata.Container.Tags {
						ps = append(ps, Response{
							ID:        v.ID,
							Name:      fmt.Sprintf("ghcr.io/%s/%s:%s", target, name, tag),
							Digest:    v.Name,
							CreatedAt: v.CreatedAt,
						})
					}
				default:
					return nil, errors.Errorf("unexpected package type. expected: %q, actual: %q", "container", v.Metadata.PackageType)
				}
			}

			if !strings.Contains(resp.Header.Get("Link"), "rel=\"next\"") {
				break
			}
		}
	}
	return ps, nil
}
