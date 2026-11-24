package salsa_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		// drop names, as host and path, a request the server cuts off
		// without an answer.
		drop string
		// rewrite maps, as host and path, a file of the mirrors to what the
		// server makes of it before answering.
		rewrite map[string]func([]byte) []byte
		// sha1Suites, when set, replaces the suites whose Sources are checked
		// against the SHA1 of their Release.
		sha1Suites []string
		// mirrorNotFound makes every Debian mirror answer 404.
		mirrorNotFound bool
		hasError       bool
	}{
		{
			// bookworm's Sources comes from the copy named by its digest,
			// sid's from its path, as sid has no such copy, and bookworm's
			// main is Sources.xz, as the Sources.gz its Release also lists
			// is not there.
			name:     "happy path",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
		},
		{
			// bookworm's Release says its files can be acquired by hash, so
			// the copy named by the digest is asked for, and its path, cut
			// off here, never is.
			name:     "Sources by hash",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			drop:     "deb.debian.org/debian/dists/bookworm/main/source/Sources.xz",
		},
		{
			// The bookworm Release lists a Sources.gz the mirror does not
			// have, which is asked for before the Sources.xz it has. That
			// request failing fails the fetch rather than passing for a
			// compression the mirror does not have.
			name:     "dropped Sources request",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			drop:     "deb.debian.org/debian/dists/bookworm/main/source/Sources.gz",
			hasError: true,
		},
		{
			// Cut off, sid's Sources is shorter than its Release says, which
			// fails the fetch rather than writing the packages read up to
			// the cut.
			name:     "truncated Sources",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			rewrite: map[string]func([]byte) []byte{
				"deb.debian.org/debian/dists/sid/main/source/Sources.gz": func(bs []byte) []byte { return bs[:len(bs)/2] },
			},
			hasError: true,
		},
		{
			// A different modification time in the gzip header leaves sid's
			// Sources the size its Release gives, and decompressing as it
			// did, but not the file the Release describes.
			name:     "Sources not matching the Release",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			rewrite: map[string]func([]byte) []byte{
				"deb.debian.org/debian/dists/sid/main/source/Sources.gz": func(bs []byte) []byte {
					bs[4] ^= 0xff
					return bs
				},
			},
			hasError: true,
		},
		{
			// With no SHA256 to check its Sources against, a suite fails the
			// fetch rather than being taken unchecked.
			name:     "Release without SHA256",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			rewrite: map[string]func([]byte) []byte{
				"security.debian.org/debian-security/dists/bookworm-security/Release": func(bs []byte) []byte {
					before, _, _ := bytes.Cut(bs, []byte("SHA256:\n"))
					return before
				},
			},
			hasError: true,
		},
		{
			// With squeeze among the suites checked against the SHA1, its
			// Sources are taken by the SHA1 of its Release, which here gives
			// no SHA256 at all.
			name:       "Sources by SHA1",
			testdata:   "testdata/fixtures/security-tracker-master.tar.gz",
			sha1Suites: []string{"squeeze"},
			rewrite: map[string]func([]byte) []byte{
				"archive.debian.org/debian/dists/squeeze/Release": func(bs []byte) []byte {
					before, _, _ := bytes.Cut(bs, []byte("SHA256:\n"))
					return before
				},
			},
		},
		{
			// The SHA1 is checked as the SHA256 is: squeeze's Sources with
			// another modification time in its gzip header keeps its size and
			// decompresses as before, but does not match it.
			name:       "Sources not matching the SHA1",
			testdata:   "testdata/fixtures/security-tracker-master.tar.gz",
			sha1Suites: []string{"squeeze"},
			rewrite: map[string]func([]byte) []byte{
				"archive.debian.org/debian/dists/squeeze/main/source/Sources.gz": func(bs []byte) []byte {
					bs[4] ^= 0xff
					return bs
				},
			},
			hasError: true,
		},
		{
			// A Release answered with anything but 200 is skipped, so without
			// the mirrors the fetch writes the tracker lists and no package.
			name:           "mirrors not found",
			testdata:       "testdata/fixtures/security-tracker-master.tar.gz",
			mirrorNotFound: true,
			hasError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Every source is fetched over https, which the in-memory network
				// serves over TLS, so a request without TLS comes from a plain http URL.
				if r.TLS == nil {
					t.Errorf("unexpected plain http request: http://%s%s", r.Host, r.URL.RequestURI())
					http.Error(w, "Client sent an HTTP request to an HTTPS server.", http.StatusBadRequest)
					return
				}

				// The in-memory network routes every mirror host here, so the
				// fixtures are keyed by the production host and path.
				fixtures := filepath.Join("testdata", "fixtures", "release")
				if r.Host == "archive.debian.org" {
					fixtures = filepath.Join("testdata", "fixtures", "archive")
				}
				rel := filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/"))
				target := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
				switch {
				case target == tt.drop:
					panic(http.ErrAbortHandler)
				case tt.rewrite[target] != nil:
					bs, err := os.ReadFile(filepath.Join(fixtures, rel))
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(tt.rewrite[target](bs)))
				case r.Host == "salsa.debian.org":
					http.ServeFile(w, r, tt.testdata)
				case tt.mirrorNotFound:
					http.NotFound(w, r)
				default:
					http.ServeFile(w, r, filepath.Join(fixtures, rel))
				}
			}))

			dir := t.TempDir()
			opts := []salsa.Option{salsa.WithHTTPClient(ts.Client()), salsa.WithDir(dir), salsa.WithRetry(0)}
			if tt.sha1Suites != nil {
				opts = append(opts, salsa.WithSHA1Suites(tt.sha1Suites))
			}
			err := salsa.Fetch(opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
