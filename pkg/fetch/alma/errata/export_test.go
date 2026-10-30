package errata

import "net/http"

// WithVersions narrows the set of AlmaLinux releases the fetcher walks. The
// production default is every supported release, which is more than a test
// wants to serve.
func WithVersions(versions []string) Option {
	return versionsOption(versions)
}

type versionsOption []string

func (v versionsOption) apply(opts *options) {
	opts.versions = v
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
