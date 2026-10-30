package cve

import "net/http"

// WithPerPage sets the page size of the listing API. Tests use a small value
// so that the fixture spans several pages and the pagination loop is
// exercised.
func WithPerPage(perPage int) Option {
	return perPageOption(perPage)
}

type perPageOption int

func (p perPageOption) apply(opts *options) {
	opts.perPage = int(p)
}

// WithHTTPClient replaces the underlying *http.Client. Tests pass the client
// of an httptest.NewTestServer, whose in-memory network routes every request
// to the test server regardless of host, so the fetcher keeps requesting the
// production URL.
func WithHTTPClient(client *http.Client) Option {
	return httpClientOption{client: client}
}

type httpClientOption struct {
	client *http.Client
}

func (c httpClientOption) apply(opts *options) {
	opts.httpClient = c.client
}
