package salsa

import (
	"net/http"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
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

// ParseDeb822 is parseDeb822, for what deb822 allows, and does not, that no
// fixture holds.
var ParseDeb822 = parseDeb822

// WithPinnedReleases replaces the suites whose Release is checked against a
// SHA256 rather than against its signature. Tests pin a suite of the
// fixtures, none of which is among the archived suites the built-in table
// holds.
func WithPinnedReleases(pins map[string]string) Option {
	return pinnedReleasesOption(pins)
}

type pinnedReleasesOption map[string]string

func (p pinnedReleasesOption) apply(opts *options) {
	opts.pinnedReleases = map[string]string(p)
}

// WithKeyRing replaces the keyring the signatures of a Release are checked
// against. Tests sign the fixture Release files with a key of their own.
func WithKeyRing(keyring openpgp.EntityList) Option {
	return keyringOption{keyring: keyring}
}

type keyringOption struct {
	keyring openpgp.EntityList
}

func (k keyringOption) apply(opts *options) {
	opts.keyring = k.keyring
}

// WithNow replaces the time the Valid-Until of a Release is compared with, the
// fixture Release files being from November 2023.
func WithNow(now time.Time) Option {
	return nowOption(now)
}

type nowOption time.Time

func (n nowOption) apply(opts *options) {
	opts.now = time.Time(n)
}

// BuiltinKeyRing reads the keyring the fetcher checks the signatures of a
// Release against.
func BuiltinKeyRing() (openpgp.EntityList, error) {
	return readKeyRing(archiveKeyring, removedKeys)
}

var (
	VerifyInRelease = verifyInRelease
	VerifyRelease   = verifyRelease
)
