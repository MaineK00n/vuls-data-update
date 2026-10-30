package cvrf

import (
	"net/http"
	"time"
)

func SetTimeNowFunc(f func() time.Time) (resetFunc func()) {
	timeNow = f
	return func() {
		timeNow = time.Now
	}
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
