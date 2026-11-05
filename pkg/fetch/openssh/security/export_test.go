package security

import (
	"net/http"
	"time"
)

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

// WithNVDWait sets the gap between NVD requests, and the backoff before
// retrying one. It is separate from WithWait because the two pace different
// hosts with different limits; see defaultNVDWait. Production has nothing to
// tune here: this fetcher sends no API key, so NVD's limit for a keyless
// caller fixes the gap. Tests pass 0 so that the fixtures are served without
// it.
func WithNVDWait(wait time.Duration) Option {
	return nvdWaitOption(wait)
}

type nvdWaitOption time.Duration

func (w nvdWaitOption) apply(opts *options) {
	opts.nvdWait = time.Duration(w)
}
