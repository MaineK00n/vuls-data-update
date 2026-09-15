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
// The granted scopes are taken from the X-OAuth-Scopes header of the "GET /user" response. Apart from
// GITHUB_TOKEN in GitHub Actions, GitHub Packages only supports a personal access token (classic), so a
// token reporting no scopes, e.g. a fine-grained personal access token, is rejected as well.
// GITHUB_TOKEN cannot access "GET /user" and gets 403 instead, and its permissions are granted by the
// workflow rather than by scopes, so 403 is logged at Info and the check is skipped. Any other unexpected
// status warns and skips the check as well.
//
// Every endpoint returns X-OAuth-Scopes for a personal access token (classic), so a cheaper one such as
// "GET /rate_limit" would do for reading the scopes. "GET /user" is used because it is the only one that
// answers GITHUB_TOKEN with 403 instead of 200 without the header, which is what tells a token that cannot
// report its scopes apart from a classic token that reports none.
//
// ref. https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages
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

	if err := Do(http.MethodGet, fmt.Sprintf("%s/user", options.baseURL), token, func(resp *http.Response) error {
		switch resp.StatusCode {
		case http.StatusOK:
			var granted []string
			for s := range strings.SplitSeq(resp.Header.Get("X-OAuth-Scopes"), ",") {
				if s := strings.TrimSpace(s); s != "" {
					granted = append(granted, s)
				}
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
				return errors.Errorf("insufficient token scopes. missing: %q, required: %q, actual: %q. use a personal access token (classic) with the required scopes. ref. https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps, https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages", missing, required, granted)
			}

			return nil
		case http.StatusUnauthorized:
			return errors.New("token is invalid or expired")
		case http.StatusForbidden:
			// GITHUB_TOKEN in GitHub Actions gets "Resource not accessible by integration" here, and its
			// permissions for GitHub Packages come from the workflow rather than from scopes, so this is expected
			slog.Info("The token cannot fetch its scopes, skip checking the token scopes", slog.Int("status", resp.StatusCode))
			return nil
		default:
			slog.Warn("Failed to fetch the token scopes, skip checking the token scopes", slog.Int("status", resp.StatusCode))
			return nil
		}
	}); err != nil {
		return errors.Wrap(err, "call GitHub API")
	}

	return nil
}
