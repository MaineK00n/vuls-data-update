package cpematch

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

// WithResultsPerPage sets the page size of the NVD API. Tests use a small
// value so that the fixture spans several pages and the pagination loop is
// exercised.
func WithResultsPerPage(resultsPerPage int) Option {
	return resultsPerPageOption(resultsPerPage)
}

type resultsPerPageOption int

func (r resultsPerPageOption) apply(opts *options) {
	opts.resultsPerPage = int(r)
}
