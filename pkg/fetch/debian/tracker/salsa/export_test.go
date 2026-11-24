package salsa

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

// WithSHA1Suites replaces the suites whose Sources are checked against the
// SHA1 of their Release. Tests name a suite of the fixtures, none of which is
// among the archived suites the built-in list holds.
func WithSHA1Suites(suites []string) Option {
	return sha1SuitesOption(suites)
}

type sha1SuitesOption []string

func (s sha1SuitesOption) apply(opts *options) {
	opts.sha1Suites = []string(s)
}

// ParseChecksums is parseChecksums, for the malformed fields no fixture
// Release holds.
var ParseChecksums = parseChecksums
