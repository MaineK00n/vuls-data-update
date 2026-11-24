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

// ShortenRetryWaits makes wait the backoff of Do between the retries of a
// connection error or a 5xx response, and the first wait for a rate limit that
// does not say how long to wait, which then doubles with each retry and gets a
// random part of up to wait on top. It leaves the waits GitHub asks for alone,
// and returns what puts the waits back. A test passes it to t.Cleanup. wait is
// to be positive, as the random part is drawn from [0, wait).
func ShortenRetryWaits(wait time.Duration) func() {
	saved := policy
	policy.waitMin, policy.waitMax, policy.rateLimitWait = wait, wait, wait
	return func() { policy = saved }
}
