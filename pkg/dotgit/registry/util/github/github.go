package github

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

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
