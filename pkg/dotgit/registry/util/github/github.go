package github

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

const baseURL = "https://api.github.com"

// Scopes required to operate on the GitHub Container Registry.
// ref. https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
const (
	ScopeReadPackages   = "read:packages"
	ScopeWritePackages  = "write:packages"
	ScopeDeletePackages = "delete:packages"
)

// impliedScopes maps a granted scope to the scopes it grants implicitly.
var impliedScopes = map[string][]string{
	ScopeWritePackages: {ScopeReadPackages},
}

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

func WithBaseURL(url string) Option {
	return baseURLOption(url)
}

func Do(method, apiurl, token string, fn func(resp *http.Response) error) error {
	u, err := url.Parse(apiurl)
	if err != nil {
		return errors.Wrap(err, "parse url")
	}

	header := make(http.Header)
	header.Set("Accept", "application/vnd.github+json")
	header.Set("X-GitHub-Api-Version", "2022-11-28")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return errors.Wrap(err, "create request")
	}
	req.Header = header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "%s: %s", method, u.String())
	}
	defer resp.Body.Close()

	if err := fn(resp); err != nil {
		return errors.Wrap(err, "process response")
	}

	return nil
}

// CheckScopes reports whether the token is set and has the required scopes.
//
// The granted scopes are taken from the X-OAuth-Scopes header of the "GET /user" response, which is
// only returned for OAuth tokens and personal access tokens (classic). A fine-grained personal
// access token or a GitHub App installation token has no scopes to report, so in that case the
// check is skipped with a warning instead of failing.
func CheckScopes(token string, required []string, opts ...Option) error {
	options := &options{
		baseURL: baseURL,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if token == "" {
		return errors.New("token is not set. specify the --token flag or the GITHUB_TOKEN environment variable")
	}

	if len(required) == 0 {
		return nil
	}

	var granted []string
	if err := Do(http.MethodGet, fmt.Sprintf("%s/user", options.baseURL), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusOK:
			for s := range strings.SplitSeq(resp.Header.Get("X-OAuth-Scopes"), ",") {
				if s := strings.TrimSpace(s); s != "" {
					granted = append(granted, s)
				}
			}
			return nil
		case http.StatusUnauthorized:
			return errors.New("token is invalid or expired")
		case http.StatusForbidden:
			return nil
		default:
			slog.Warn("Unexpected response status while fetching the token scopes, skip checking the token scopes", slog.Int("status", resp.StatusCode))
			return nil
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}

	if len(granted) == 0 {
		slog.Warn("The token does not report its scopes, skip checking the token scopes", slog.Any("required", required))
		return nil
	}

	missing := make([]string, 0, len(required))
	for _, r := range required {
		if !slices.ContainsFunc(granted, func(g string) bool {
			return g == r || slices.Contains(impliedScopes[g], r)
		}) {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return errors.Errorf("insufficient token scopes. missing: %q, required: %q, actual: %q. ref. https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps", missing, required, granted)
	}

	return nil
}
