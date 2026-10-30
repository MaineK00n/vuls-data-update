package v1

import "net/http"

// WithFeeds narrows the set of NVD feeds the fetcher walks. The production
// default is "modified", "recent" and every year since oldestYear, which is
// more than a test wants to serve.
func WithFeeds(feeds []string) Option {
	return feedsOption(feeds)
}

type feedsOption []string

func (f feedsOption) apply(opts *options) {
	opts.feeds = f
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
