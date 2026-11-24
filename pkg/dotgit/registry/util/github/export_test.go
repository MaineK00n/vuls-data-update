package github

import (
	"net/http"
	"time"
)

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

// RateLimitBackoff is rateLimitBackoff.
var RateLimitBackoff = rateLimitBackoff

// ShortenRetryWaits makes every wait of Do between retries, a rate limit that
// does not say how long to wait included, wait instead, and returns what puts
// the waits back. A test passes it to t.Cleanup.
func ShortenRetryWaits(wait time.Duration) func() {
	saved := policy
	policy.waitMin, policy.waitMax, policy.rateLimitWait = wait, wait, wait
	return func() { policy = saved }
}
