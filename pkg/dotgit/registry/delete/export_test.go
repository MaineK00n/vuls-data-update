package delete

import (
	"net/http"
	"time"
)

// WithHTTPClient replaces the *http.Client used to call the GitHub API.
// Tests pass the client of an httptest.NewTestServer, whose in-memory network
// routes every request to the test server regardless of host, so the caller
// keeps requesting the production API URL.
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

// WithDeleteInterval replaces the least time from one DELETE to the start of
// the next version, a second, so that a test of many deletes does not sleep
// for seconds.
//
// This file is only compiled into the test binary, so the knob is not part of
// the production API.
func WithDeleteInterval(interval time.Duration) Option {
	return deleteIntervalOption(interval)
}

type deleteIntervalOption time.Duration

func (i deleteIntervalOption) apply(opts *options) {
	opts.deleteInterval = time.Duration(i)
}
