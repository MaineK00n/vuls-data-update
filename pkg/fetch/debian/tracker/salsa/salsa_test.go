package salsa_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	// The fixture Release files are signed as they are served, by signer,
	// whose key is the keyring the fetcher is given, unless a case names
	// other signers.
	signer, err := newSigner("salsa test signer")
	if err != nil {
		t.Fatalf("new signer. err: %v", err)
	}
	stranger, err := newSigner("salsa test stranger")
	if err != nil {
		t.Fatalf("new signer. err: %v", err)
	}

	squeezeRelease, err := os.ReadFile(filepath.Join("testdata", "fixtures", "archive", "debian", "dists", "squeeze", "Release"))
	if err != nil {
		t.Fatalf("read squeeze Release. err: %v", err)
	}

	tests := []struct {
		name     string
		testdata string
		// drop names, as host and path, a request the server cuts off
		// without an answer.
		drop string
		// rewrite maps, as host and path, a file of the mirrors to what the
		// server makes of it before answering, and, for a Release, before
		// signing it.
		rewrite map[string]func([]byte) []byte
		// tamper maps, as host and path, a file of the mirrors to what the
		// server makes of it once a Release is signed: an InRelease or a
		// Release no longer matching its signature.
		tamper map[string]func([]byte) []byte
		// signers sign the Release files, an InRelease with all of them and
		// a Release.gpg in an armored block each; signer alone if unset.
		signers []*openpgp.Entity
		// noInRelease makes the mirrors answer 404 for every InRelease, so
		// that Release and Release.gpg are taken.
		noInRelease bool
		// sha1Suites, when set, replaces the suites whose Sources are checked
		// against the SHA1 of their Release.
		sha1Suites []string
		// pinnedReleases, when set, replaces the suites whose Release is
		// checked against a SHA256 rather than against its signature.
		pinnedReleases map[string]string
		// now, when set, replaces the time Valid-Until is compared with,
		// 14 November 2023, when every fixture Release is good.
		now time.Time
		// mirrorNotFound makes every Debian mirror answer 404.
		mirrorNotFound bool
		hasError       bool
	}{
		{
			// Every Release comes as an InRelease signed by the fetcher's key.
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
			// Without an InRelease, the Release is taken with its Release.gpg.
			name:        "Release.gpg without InRelease",
			testdata:    "testdata/fixtures/security-tracker-master.tar.gz",
			noInRelease: true,
		},
		{
			// A Release.gpg can hold an armored block per signature, as the
			// stable release key's is appended to the archive key's. A block
			// signed by a key the fetcher does not know keeps it from neither
			// the block signed by one it does nor the Release.
			name:        "Release.gpg in two armored blocks",
			testdata:    "testdata/fixtures/security-tracker-master.tar.gz",
			signers:     []*openpgp.Entity{stranger, signer},
			noInRelease: true,
		},
		{
			// A Release signed by no key of the fetcher's keyring fails the
			// fetch.
			name:     "signature by an unknown key",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			signers:  []*openpgp.Entity{stranger},
			hasError: true,
		},
		{
			// So does an InRelease whose text changed after it was signed.
			name:     "InRelease changed after signing",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			tamper: map[string]func([]byte) []byte{
				"deb.debian.org/debian/dists/sid/InRelease": func(bs []byte) []byte {
					return bytes.Replace(bs, []byte("Suite: unstable"), []byte("Suite: testing"), 1)
				},
			},
			hasError: true,
		},
		{
			// And a Release that changed after its Release.gpg was made.
			name:        "Release changed after signing",
			testdata:    "testdata/fixtures/security-tracker-master.tar.gz",
			noInRelease: true,
			tamper: map[string]func([]byte) []byte{
				"deb.debian.org/debian/dists/sid/Release": func(bs []byte) []byte {
					return bytes.Replace(bs, []byte("Suite: unstable"), []byte("Suite: testing"), 1)
				},
			},
			hasError: true,
		},
		{
			// A Release signed as it should be, but naming another suite as
			// its Codename, here sid's naming bookworm, fails the fetch.
			name:     "Release of another suite",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			rewrite: map[string]func([]byte) []byte{
				"deb.debian.org/debian/dists/sid/Release": func(bs []byte) []byte {
					return bytes.Replace(bs, []byte("Codename: sid"), []byte("Codename: bookworm"), 1)
				},
			},
			hasError: true,
		},
		{
			// The Release files of bookworm-security, bookworm-backports and
			// sid are good until 19 and 20 November 2023, and fail the fetch
			// once past that.
			name:     "Release past its Valid-Until",
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
			now:      time.Date(2023, time.December, 1, 0, 0, 0, 0, time.UTC),
			hasError: true,
		},
		{
			// A pinned Release is checked against the SHA256 it is pinned to,
			// and its signatures, unreadable here, are not asked for.
			name:           "pinned Release",
			testdata:       "testdata/fixtures/security-tracker-master.tar.gz",
			pinnedReleases: map[string]string{"squeeze": fmt.Sprintf("%x", sha256.Sum256(squeezeRelease))},
			tamper: map[string]func([]byte) []byte{
				"archive.debian.org/debian/dists/squeeze/InRelease":   func([]byte) []byte { return []byte("not signed") },
				"archive.debian.org/debian/dists/squeeze/Release.gpg": func([]byte) []byte { return []byte("not signed") },
			},
		},
		{
			// A pinned Release other than the one it is pinned to fails the
			// fetch.
			name:           "pinned Release changed",
			testdata:       "testdata/fixtures/security-tracker-master.tar.gz",
			pinnedReleases: map[string]string{"squeeze": fmt.Sprintf("%x", sha256.Sum256(squeezeRelease))},
			rewrite: map[string]func([]byte) []byte{
				"archive.debian.org/debian/dists/squeeze/Release": func(bs []byte) []byte {
					return bytes.Replace(bs, []byte("Suite: oldoldstable"), []byte("Suite: oldstable"), 1)
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
			signers := tt.signers
			if signers == nil {
				signers = []*openpgp.Entity{signer}
			}

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
				target := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
				switch {
				case target == tt.drop:
					panic(http.ErrAbortHandler)
				case r.Host == "salsa.debian.org":
					http.ServeFile(w, r, tt.testdata)
					return
				case tt.mirrorNotFound, tt.noInRelease && path.Base(r.URL.Path) == "InRelease":
					http.NotFound(w, r)
					return
				}

				fixtures := filepath.Join("testdata", "fixtures", "release")
				if r.Host == "archive.debian.org" {
					fixtures = filepath.Join("testdata", "fixtures", "archive")
				}
				bs, err := serve(fixtures, r.Host, r.URL.Path, tt.rewrite, tt.tamper, signers)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					http.NotFound(w, r)
				case err != nil:
					http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
				default:
					http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(bs))
				}
			}))

			now := time.Date(2023, time.November, 14, 0, 0, 0, 0, time.UTC)
			if !tt.now.IsZero() {
				now = tt.now
			}
			dir := t.TempDir()
			opts := []salsa.Option{salsa.WithHTTPClient(ts.Client()), salsa.WithDir(dir), salsa.WithRetry(0), salsa.WithKeyRing(openpgp.EntityList{signer}), salsa.WithNow(now)}
			if tt.sha1Suites != nil {
				opts = append(opts, salsa.WithSHA1Suites(tt.sha1Suites))
			}
			if tt.pinnedReleases != nil {
				opts = append(opts, salsa.WithPinnedReleases(tt.pinnedReleases))
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

func TestParseChecksums(t *testing.T) {
	type args struct {
		field string
		hash  string
	}
	tests := []struct {
		name string
		args args
		// want lists the paths the checksums are read for.
		want    []string
		wantErr bool
	}{
		{
			name: "SHA256",
			args: args{
				field: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/source/Sources 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275 32 main/source/Sources.xz",
				hash:  "SHA256",
			},
			want: []string{"main/source/Sources", "main/source/Sources.xz"},
		},
		{
			name: "SHA1",
			args: args{field: "da39a3ee5e6b4b0d3255bfef95601890afd80709 0 main/source/Sources", hash: "SHA1"},
			want: []string{"main/source/Sources"},
		},
		{
			name:    "entry without its size",
			args:    args{field: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 main/source/Sources", hash: "SHA256"},
			wantErr: true,
		},
		{
			// The digest goes into the by-hash URL.
			name:    "digest not in hex",
			args:    args{field: fmt.Sprintf("%s 0 main/source/Sources", strings.Repeat("../", 21)+"x"), hash: "SHA256"},
			wantErr: true,
		},
		{
			name:    "SHA1 digest as SHA256",
			args:    args{field: "da39a3ee5e6b4b0d3255bfef95601890afd80709 0 main/source/Sources", hash: "SHA256"},
			wantErr: true,
		},
		{
			name:    "negative size",
			args:    args{field: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -1 main/source/Sources", hash: "SHA256"},
			wantErr: true,
		},
		{
			name:    "size not a number",
			args:    args{field: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0x0 main/source/Sources", hash: "SHA256"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := salsa.ParseChecksums(tt.args.field, tt.args.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseChecksums() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, slices.Sorted(maps.Keys(got))); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

// serve makes what a mirror on host answers for p from the fixtures: the file
// at p, as rewrite has it, or for an InRelease or a Release.gpg, the Release
// beside it, as rewrite has it, signed by signers; then as tamper has it.
func serve(fixtures, host, p string, rewrite, tamper map[string]func([]byte) []byte, signers []*openpgp.Entity) ([]byte, error) {
	read := func(p string) ([]byte, error) {
		bs, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(strings.TrimPrefix(p, "/"))))
		if err != nil {
			return nil, errors.Wrapf(err, "read %s", p)
		}
		if f := rewrite[fmt.Sprintf("%s%s", host, p)]; f != nil {
			bs = f(bs)
		}
		return bs, nil
	}

	var bs []byte
	switch path.Base(p) {
	case "InRelease", "Release.gpg":
		release, err := read(path.Join(path.Dir(p), "Release"))
		if err != nil {
			return nil, errors.Wrap(err, "read Release")
		}
		sign := detachSign
		if path.Base(p) == "InRelease" {
			sign = clearSign
		}
		if bs, err = sign(release, signers); err != nil {
			return nil, errors.Wrap(err, "sign Release")
		}
	default:
		var err error
		if bs, err = read(p); err != nil {
			return nil, err
		}
	}
	if f := tamper[fmt.Sprintf("%s%s", host, p)]; f != nil {
		bs = f(bs)
	}
	return bs, nil
}

// newSigner makes an entity with a new ed25519 key.
func newSigner(name string) (*openpgp.Entity, error) {
	e, err := openpgp.NewEntity(name, "", "", &packet.Config{Algorithm: packet.PubKeyAlgoEd25519})
	if err != nil {
		return nil, errors.Wrap(err, "new entity")
	}
	return e, nil
}

// clearSign makes an InRelease of release, signed by every signer.
func clearSign(release []byte, signers []*openpgp.Entity) ([]byte, error) {
	keys := make([]*packet.PrivateKey, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.PrivateKey)
	}

	var buf bytes.Buffer
	w, err := clearsign.EncodeMulti(&buf, keys, nil)
	if err != nil {
		return nil, errors.Wrap(err, "encode")
	}
	if _, err := w.Write(release); err != nil {
		return nil, errors.Wrap(err, "write")
	}
	if err := w.Close(); err != nil {
		return nil, errors.Wrap(err, "close")
	}
	return buf.Bytes(), nil
}

// detachSign makes a Release.gpg of release, with the signature of each
// signer in an armored block of its own.
func detachSign(release []byte, signers []*openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	for _, s := range signers {
		if err := openpgp.ArmoredDetachSign(&buf, []*openpgp.Entity{s}, bytes.NewReader(release), nil); err != nil {
			return nil, errors.Wrap(err, "sign")
		}
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

func TestBuiltinKeyRing(t *testing.T) {
	keyring, err := salsa.BuiltinKeyRing()
	if err != nil {
		t.Fatalf("read keyring. err: %v", err)
	}

	got := make(map[string]string, len(keyring))
	for _, e := range keyring {
		got[fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)] = strings.Join(slices.Sorted(maps.Keys(e.Identities)), ", ")
	}

	// The primary keys of debian-archive-keyring 2025.1: those of
	// debian-archive-keyring.pgp, which are the ones
	// https://ftp-master.debian.org/keys.html gives, and those of
	// debian-archive-removed-keys.pgp.
	want := map[string]string{
		"1F89983E0081FDE018F3CC9673A4F27B8DD47936": "Debian Archive Automatic Signing Key (11/bullseye) <ftpmaster@debian.org>",
		"AC530D520F2F3269F5E98313A48449044AAD5C5D": "Debian Security Archive Automatic Signing Key (11/bullseye) <ftpmaster@debian.org>",
		"A4285295FC7B1A81600062A9605C66F00D6C9793": "Debian Stable Release Key (11/bullseye) <debian-release@lists.debian.org>",
		"4D64FEC119C2029067D6E791F8D2585B8783D481": "Debian Stable Release Key (12/bookworm) <debian-release@lists.debian.org>",
		"B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8": "Debian Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.org>",
		"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0": "Debian Security Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.org>",
		"04B54C3CDCA79751B16BC6B5225629DF75B188BD": "Debian Archive Automatic Signing Key (13/trixie) <ftpmaster@debian.org>",
		"5E04A1E3223A19A20706E20F9904613D4CCE68C6": "Debian Security Archive Automatic Signing Key (13/trixie) <ftpmaster@debian.org>",
		"41587F7DB8C774BCCF131416762F67A0B2C39DE4": "Debian Stable Release Key (13/trixie) <debian-release@lists.debian.org>",

		"D051FE3A848DCABD4625787A6FFA8EF91DB114E0": "Debian Archive Automatic Signing Key (2004) <ftpmaster@debian.org>",
		"4C7A8E5E9454FE3FAE1E78ADF1D53D8C4F368D5D": "Debian Archive Automatic Signing Key (2005) <ftpmaster@debian.org>",
		"C20CA1D9499DECBBD8BDACF9E415B2B4B5F5BBED": "Debian AMD64 Archive Key <debian-amd64@lists.debian.org>",
		"084750FC01A6D388A643D869010908312D230C5F": "Debian Archive Automatic Signing Key (2006) <ftpmaster@debian.org>",
		"A99951DAF9BB569BDB50AD90A70DAF536070D3A1": "Debian Archive Automatic Signing Key (4.0/etch) <ftpmaster@debian.org>",
		"7EA391D72477203B58C04FBCB5D0C804ADB11277": "Etch Stable Release Key <debian-release@lists.debian.org>",
		"6039406A4EDCE124CF087B0AEC61E0B0BBE55AB3": "Debian-Volatile Archive Automatic Signing Key (4.0/etch)",
		"150C8614919D8446E01E83AF9AA38DCD55BE302B": "Debian Archive Automatic Signing Key (5.0/lenny) <ftpmaster@debian.org>",
		"7F5A44454C724A65CBCD4FB14D270D06F42584E6": "Lenny Stable Release Key <debian-release@lists.debian.org>",
		"F6CFDE3061333CE2A43FDAF0DFD993306D849617": "Debian-Volatile Archive Automatic Signing Key (5.0/lenny)",
		"0E4EDE2C7F3E1FC0D033800E64481591B98321F9": "Squeeze Stable Release Key <debian-release@lists.debian.org>",
		"9FED2BCBDCD29CDF762678CBAED4B06F473041FA": "Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>",
		"A1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553": "Debian Archive Automatic Signing Key (7.0/wheezy) <ftpmaster@debian.org>",
		"ED6D65271AACF0FF15D123036FB2A1C265FFB764": "Wheezy Stable Release Key <debian-release@lists.debian.org>",
		"75DDC3C4A499F1A18CB5F3C8CBF8D6FD518E17E1": "Jessie Stable Release Key <debian-release@lists.debian.org>",
		"126C0D24BD8A2942CC7DF8AC7638D0442B90D010": "Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>",
		"D21169141CECD440F2EB8DDA9D6D8F6BC857C906": "Debian Security Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>",
		"067E3C456BAE240ACEE88F6FEF0F382A1A7B6500": "Debian Stable Release Key (9/stretch) <debian-release@lists.debian.org>",
		"E1CF20DDFFE4B89E802658F1E0B11894F66AEC98": "Debian Archive Automatic Signing Key (9/stretch) <ftpmaster@debian.org>",
		"6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9": "Debian Security Archive Automatic Signing Key (9/stretch) <ftpmaster@debian.org>",
		"6D33866EDD8FFA41C0143AEDDCC9EFBF77E11517": "Debian Stable Release Key (10/buster) <debian-release@lists.debian.org>",
		"80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE": "Debian Archive Automatic Signing Key (10/buster) <ftpmaster@debian.org>",
		"5E61B217265DA9807A23C5FF4DFAB270CAA96DFA": "Debian Security Archive Automatic Signing Key (10/buster) <ftpmaster@debian.org>",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-expected +got):\n%s", diff)
	}
}

func TestVerifyRelease(t *testing.T) {
	keyring, err := salsa.BuiltinKeyRing()
	if err != nil {
		t.Fatalf("read keyring. err: %v", err)
	}

	// The Release of jessie's security suite as archive.debian.org serves
	// it, signed in July 2020 by the jessie and stretch security archive
	// keys, which have expired since: a signature is checked against the key
	// as it was when it signed.
	dir := filepath.Join("testdata", "fixtures", "signed", "debian-security", "dists", "jessie", "updates")
	inRelease, err := os.ReadFile(filepath.Join(dir, "InRelease"))
	if err != nil {
		t.Fatalf("read InRelease. err: %v", err)
	}
	release, err := os.ReadFile(filepath.Join(dir, "Release"))
	if err != nil {
		t.Fatalf("read Release. err: %v", err)
	}
	releaseGPG, err := os.ReadFile(filepath.Join(dir, "Release.gpg"))
	if err != nil {
		t.Fatalf("read Release.gpg. err: %v", err)
	}

	tests := []struct {
		name      string
		inRelease []byte
		release   []byte
		sigs      []byte
		wantErr   bool
	}{
		{
			name:      "InRelease",
			inRelease: inRelease,
		},
		{
			name:    "Release with Release.gpg",
			release: release,
			sigs:    releaseGPG,
		},
		{
			name:      "InRelease changed",
			inRelease: bytes.Replace(inRelease, []byte("Codename: jessie"), []byte("Codename: wheezy"), 1),
			wantErr:   true,
		},
		{
			name:    "Release changed",
			release: bytes.Replace(release, []byte("Codename: jessie"), []byte("Codename: wheezy"), 1),
			sigs:    releaseGPG,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			switch {
			case tt.inRelease != nil:
				var text []byte
				text, err = salsa.VerifyInRelease(keyring, tt.inRelease)
				if err == nil {
					// The text signed is the Release.
					if diff := cmp.Diff(strings.TrimRight(string(release), "\n"), strings.TrimRight(string(text), "\n")); diff != "" {
						t.Errorf("(-expected +got):\n%s", diff)
					}
				}
			default:
				err = salsa.VerifyRelease(keyring, tt.release, tt.sigs)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("verify. err: %v, wantErr: %v", err, tt.wantErr)
			}
		})
	}
}
