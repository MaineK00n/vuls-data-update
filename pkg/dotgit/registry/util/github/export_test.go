package github

import "net/http"

// WithHTTPClient replaces the *http.Client CheckScopes calls the GitHub API
// with. Tests pass the client of an httptest.NewTestServer, whose in-memory
// network routes every request to the test server regardless of host, so the
// production API URL is used as-is.
//
// This file is only compiled into the test binary, so the knob is not part of
// the production API.
func WithHTTPClient(client *http.Client) Option {
	return httpClientOption{client: client}
}

type httpClientOption struct {
	client *http.Client
}

func (c httpClientOption) apply(opts *options) {
	opts.httpClient = c.client
}
