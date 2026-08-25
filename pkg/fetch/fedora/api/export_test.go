package api

import "net/http"

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

// WithRowsPerPage sets the page size of the Bodhi API. Tests use a small
// value so that the fixture spans several pages and the pagination loop is
// exercised.
func WithRowsPerPage(rowsPerPage int) Option {
	return rowsPerPageOption(rowsPerPage)
}

type rowsPerPageOption int

func (r rowsPerPageOption) apply(opts *options) {
	opts.rowsPerPage = int(r)
}
