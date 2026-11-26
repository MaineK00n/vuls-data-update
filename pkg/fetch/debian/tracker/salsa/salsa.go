package salsa

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/bzip2"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz?path=data"

var (
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L152-153
	pkgVersionRegexp = regexp.MustCompile(fmt.Sprintf("^\\s+%s\\s*$", `(?:\[(?P<release>[a-z]+)\]\s)?-\s(?P<package>[A-Za-z0-9:.+-]+)\s*`+`(?:\s(?P<version>[A-Za-z0-9:.+~-]+)\s*)?(?:\s\((?P<inner>.*)\))?`))
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L174-175
	pkgPseudoRegexp = regexp.MustCompile(fmt.Sprintf("^\\s+%s\\s*$", `(?:\[(?P<release>[a-z]+)\]\s)?-\s(?P<package>[A-Za-z0-9:.+-]+)`+`\s+<(?P<kind>[a-z-]+)>\s*(?:\s\((?P<inner>.*)\))?`))
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L207
	xrefRegexp = regexp.MustCompile(fmt.Sprintf("^\\s+%s\\s*$", `\{(?P<xref>.*)\}`))
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L217
	flagRegexp = regexp.MustCompile(fmt.Sprintf("^\\s+%s\\s*$", `(?P<type>RESERVED|REJECTED)`))
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L219
	stringRegexp = regexp.MustCompile(fmt.Sprintf("^\\s+%s\\s*$", `(?P<type>NOT-FOR-US|NOTE|TODO):\s+(?P<description>\S.*)`))

	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L118
	pkgUrgencyRegexp = regexp.MustCompile(`(?P<flag>unimportant|low|medium|high)`)
	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L125
	pkgBugRegexp = regexp.MustCompile(`bug #(?P<no>\d+)`)

	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L172
	pseudoFreeText = []string{
		"no-dsa",
		"not-affected",
		"end-of-life",
		"ignored",
		"postponed",
	}

	// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L173
	pseudoStruct = []string{
		"unfixed",
		"removed",
		"itp",
		"undetermined",
	}

	releaseStable   = "https://deb.debian.org/debian"
	releaseSecurity = "https://security.debian.org/debian-security"
	releaseBackport = "https://deb.debian.org/debian"
	archiveStable   = "https://archive.debian.org/debian"
	archiveSecurity = "https://archive.debian.org/debian-security"
	archiveBackport = "https://archive.debian.org/debian-backports"
	codenames       = []string{"hamm", "slink", "potato", "woody", "sarge", "etch", "lenny", "squeeze", "wheezy", "jessie", "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "sid"}

	// sha1Suites lists the suites, by their path under dists, whose Release
	// gives no SHA256 but MD5Sum and SHA1 only: the oldest on
	// archive.debian.org. Their Sources are checked against the SHA1.
	sha1Suites = []string{"potato", "woody", "woody/updates", "sarge-backports"}

	// pinnedReleases maps the suites, by their path under dists, whose Release
	// is checked against the SHA256 given here rather than against its
	// signature: the suites of archive.debian.org up to lenny, signed in ways
	// go-crypto rejects (v3 signature packets, DSA keys, SHA-1 digests) or
	// with keys Debian no longer ships. Their Release, dated 2002 to 2012, has
	// not changed since the suite was archived.
	pinnedReleases = map[string]string{
		"potato":          "907ade766e8b97eaf25ec86fc55f3c6e8b3a075f0781f2b98955f5924957762d",
		"woody":           "92b4fbb707b2cb0c78be02e1495fdc7cb29410bbdc9caf687b099710d0fc26a8",
		"woody/updates":   "bdf05ae60f497925e7702e62482cf0404166ca0ca138f19fe46c21c01488d07b",
		"sarge":           "a37d60625ab8ec3d3c36f2893b68f6114d53a422c74722d36cefca283043476b",
		"sarge/updates":   "0719c963d1333fa33ee500518034954d49ef3a47d2ec059387aff61324c959d2",
		"sarge-backports": "4b3f707883b625c5225606915a78522ee7bff07e1ff37764c47f3af3bcbf1d4d",
		"etch":            "9b7225f7f5be9697d5fa3b3141fff54cc4c47d482fc70e544da003f242f8ada7",
		"etch/updates":    "f57bb099a3d51b09af43be985e6a16ca84a46ce467a5309e4cdc6ef5f5ee3475",
		"etch-backports":  "e84fe1b3b85954ed44755cf8eb7a6daace7ce261008be9bf0f4fdc8e38dc7257",
		"lenny":           "91c97659233014f2aa1395bee3ec90ef3d8ac63619215c0b8aeb04f7dd128664",
		"lenny/updates":   "82efcece8177ca4c5f9cbba82500bc36fe2d38ef8502d9f860d6e61e2286029d",
		"lenny-backports": "c0e9754135dce02e25bc3f588239307fa398d20243607f20dc52b75e9f0e52a3",
	}

	// archiveKeyring and removedKeys are debian-archive-keyring.pgp and
	// debian-archive-removed-keys.pgp of debian-archive-keyring 2025.1: the
	// archive keys in use, and the retired ones, which signed the Release of
	// the suites archived since. A Release is signed with the keys of the
	// last two releases of Debian, so once neither is among these, the fetch
	// fails until they are taken from a newer debian-archive-keyring.
	//
	//go:embed keyring/debian-archive-keyring.pgp
	archiveKeyring []byte
	//go:embed keyring/debian-archive-removed-keys.pgp
	removedKeys []byte
)

type options struct {
	dataURL string
	dir     string
	retry   int
	mirror  Mirror

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client

	// sha1Suites, pinnedReleases, keyring and now are only ever replaced by
	// WithSHA1Suites, WithPinnedReleases, WithKeyRing and WithNow, which live
	// in export_test.go and are therefore absent from the production build.
	sha1Suites     []string
	pinnedReleases map[string]string
	keyring        openpgp.EntityList
	now            time.Time
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

type Mirror struct {
	ReleaseStable   string
	ReleaseSecurity string
	ReleaseBackport string
	ArchiveStable   string
	ArchiveSecurity string
	ArchiveBackport string
}

func Fetch(opts ...Option) error {
	keyring, err := readKeyRing(archiveKeyring, removedKeys)
	if err != nil {
		return errors.Wrap(err, "read embedded keyrings")
	}

	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "debian", "tracker", "salsa"),
		retry:   3,
		mirror: Mirror{
			ReleaseStable:   releaseStable,
			ReleaseSecurity: releaseSecurity,
			ReleaseBackport: releaseBackport,
			ArchiveStable:   archiveStable,
			ArchiveSecurity: archiveSecurity,
			ArchiveBackport: archiveBackport,
		},
		sha1Suites:     sha1Suites,
		pinnedReleases: pinnedReleases,
		keyring:        keyring,
		now:            time.Now(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Debian Security Tracker Salsa repository")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch salsa repository")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		d, f := filepath.Split(hdr.Name)
		switch f {
		case "config.json":
			slog.Info("Fetch Package Source")
			archives, releases, err := parseConfig(tr)
			if err != nil {
				return errors.Wrap(err, "parse config")
			}

			for _, codename := range append(archives, releases...) {
				m, err := options.fetchSource(codename, slices.Contains(archives, codename))
				if err != nil {
					return errors.Wrapf(err, "fetch debian %s source", codename)
				}

				for repo, mm := range m {
					for section, mmm := range mm {
						slog.Info("Fetched Debian", slog.String("codename", codename), slog.String("repo", repo), slog.String("section", section))
						bar := progressbar.Default(int64(len(mmm)))
						for name, source := range mmm {
							p, err := utilfilepath.Join(options.dir, "packages", codename, repo, section, name[:1], fmt.Sprintf("%s.json", name))
							if err != nil {
								return errors.Wrap(err, "join")
							}

							if err := util.Write(p, source, util.WithAllowInvalidUTF8(true)); err != nil {
								return errors.Wrapf(err, "write %s", p)
							}
							_ = bar.Add(1)
						}
						_ = bar.Close()
					}
				}
			}
		case "list":
			switch filepath.Base(d) {
			case "CPE":
				slog.Info("Read CPE/list")
				cpes, err := cpelist(tr)
				if err != nil {
					return errors.Wrap(err, "parse CPE/list")
				}

				bar := progressbar.Default(int64(len(cpes)))
				for _, cpe := range cpes {
					p, err := utilfilepath.Join(options.dir, "CPE", cpe.Package[:1], fmt.Sprintf("%s.json", cpe.Package))
					if err != nil {
						return errors.Wrap(err, "join")
					}

					if err := util.Write(p, cpe); err != nil {
						return errors.Wrapf(err, "write %s", p)
					}
					_ = bar.Add(1)
				}
				_ = bar.Close()
			case "CVE":
				slog.Info("Read CVE/list")
				bugs, err := cvelist(tr)
				if err != nil {
					return errors.Wrap(err, "parse CVE/list")
				}

				bar := progressbar.Default(int64(len(bugs)))
				for _, bug := range bugs {
					switch {
					case strings.HasPrefix(bug.Header.Name, "CVE-"):
						y := strings.Split(bug.Header.Name, "-")[1]
						p, err := utilfilepath.Join(options.dir, "CVE", y, fmt.Sprintf("%s.json", bug.Header.Name))
						if err != nil {
							return errors.Wrap(err, "join")
						}

						if err := util.Write(p, bug); err != nil {
							return errors.Wrapf(err, "write %s", p)
						}
						_ = bar.Add(1)
					case strings.HasPrefix(bug.Header.Name, "TEMP-"):
						p, err := utilfilepath.Join(options.dir, "CVE", "TEMP", fmt.Sprintf("%s.json", bug.Header.Name))
						if err != nil {
							return errors.Wrap(err, "join")
						}

						if err := util.Write(p, bug); err != nil {
							return errors.Wrapf(err, "write %s", p)
						}
						_ = bar.Add(1)
					default:
						return errors.Errorf("invalid header name: %q", bug.Header.Name)
					}
				}
				_ = bar.Close()
			case "DLA":
				slog.Info("Read DLA/list")
				bugs, err := dlalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DLA/list")
				}

				bar := progressbar.Default(int64(len(bugs)))
				for _, bug := range bugs {
					p, err := utilfilepath.Join(options.dir, "DLA", fmt.Sprintf("%s.json", bug.Header.Name))
					if err != nil {
						return errors.Wrap(err, "join")
					}

					if err := util.Write(p, bug); err != nil {
						return errors.Wrapf(err, "write %s", p)
					}
					_ = bar.Add(1)
				}
				_ = bar.Close()
			case "DSA":
				slog.Info("Read DSA/list")
				bugs, err := dsalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DSA/list")
				}

				bar := progressbar.Default(int64(len(bugs)))
				for _, bug := range bugs {
					p, err := utilfilepath.Join(options.dir, "DSA", fmt.Sprintf("%s.json", bug.Header.Name))
					if err != nil {
						return errors.Wrap(err, "join")
					}

					if err := util.Write(p, bug); err != nil {
						return errors.Wrapf(err, "write %s", p)
					}
					_ = bar.Add(1)
				}
				_ = bar.Close()
			case "DTSA":
				slog.Info("Read DTSA/list")
				bugs, err := dtsalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DTSA/list")
				}

				bar := progressbar.Default(int64(len(bugs)))
				for _, bug := range bugs {
					p, err := utilfilepath.Join(options.dir, "DTSA", fmt.Sprintf("%s.json", bug.Header.Name))
					if err != nil {
						return errors.Wrap(err, "join")
					}

					if err := util.Write(p, bug); err != nil {
						return errors.Wrapf(err, "write %s", p)
					}
					_ = bar.Add(1)
				}
				_ = bar.Close()
			default:
			}
		default:
		}
	}

	if err := util.EnsureWritten(options.dir, util.WithRequire("packages", "CPE", "CVE", "DLA", "DSA", "DTSA")); err != nil {
		return errors.Wrapf(err, "ensure written %s", options.dir)
	}

	return nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/bin/compare-nvd-cve#L133
func cpelist(r io.Reader) ([]CPE, error) {
	var cpes []CPE

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		lhs, rhs, ok := strings.Cut(line, ";")
		if !ok {
			slog.Warn("unexpected CPE format", slog.String("expected", "<Package>;<CPE>"), slog.String("actual", line))
			continue
		}
		cpes = append(cpes, CPE{
			Line:    line,
			Package: lhs,
			CPE:     rhs,
		})
	}
	if err := s.Err(); err != nil {
		return nil, errors.Wrap(err, "scanner encounter error")
	}

	return cpes, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L300
func cvelist(r io.Reader) ([]Bug, error) {
	reHeader := regexp.MustCompile(`^(?P<name>(?:CVE-\d{4}-(?:\d{4,}|XXXX)|TEMP-\d+-\S+))\s*(?P<description>.*?)\s*$`)
	parseheader := func(line string) []string {
		match := reHeader.FindStringSubmatch(line)
		if len(match) == 0 {
			return nil
		}

		if desc := match[reHeader.SubexpIndex("description")]; desc != "" {
			if desc[:1] == "(" && desc[len(desc)-1:] != ")" {
				slog.Warn("missing ')'", slog.String("line", line))
			}
			if desc[:1] == "[" && desc[len(desc)-1:] != "]" {
				slog.Warn("missing ']'", slog.String("line", line))
			}
		}
		return match
	}

	finish := func(header []string, line string, anns []any) Bug {
		name, desc := header[reHeader.SubexpIndex("name")], header[reHeader.SubexpIndex("description")]

		// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/bugs.py#L402
		if strings.HasSuffix(name, "-XXXX") {
			var bugno int
		outer:
			for _, ann := range anns {
				a, ok := ann.(PackageAnnotation)
				if !ok {
					continue
				}

				for _, flag := range a.Flags {
					f, ok := flag.(PackageBugAnnotation)
					if ok {
						bugno = f.Bug
						break outer
					}
				}
			}

			d := desc
			switch {
			case strings.HasPrefix(desc, "["):
				d = strings.TrimPrefix(strings.TrimSuffix(desc, "]"), "[")
			case strings.HasPrefix(desc, "("):
				d = strings.TrimPrefix(strings.TrimSuffix(desc, ")"), "(")
			}

			h := fmt.Sprintf("%x", md5.Sum([]byte(d)))
			name = fmt.Sprintf("TEMP-%07d-%s", bugno, strings.ToUpper(h[:6]))
		}

		return Bug{Header: &Header{
			Line:        line,
			Name:        name,
			Description: desc,
		}, Annotations: anns}
	}

	bugs, err := parselist(r, parseheader, finish)
	if err != nil {
		return nil, errors.Wrap(err, "parselist")
	}

	return bugs, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L385
func dsalist(r io.Reader) ([]Bug, error) {
	reHeader := regexp.MustCompile(`^\[(?P<day>\d\d) (?P<month>[A-Z][a-z][a-z]) (?P<year>\d{4})\] ` + `(?P<name>DSA-\d+(?:-\d+)?)\s+` + `(?P<description>.*?)\s*$`)
	parseheader := func(line string) []string {
		match := reHeader.FindStringSubmatch(line)
		if len(match) == 0 {
			return nil
		}
		return match
	}

	finish := func(header []string, line string, anns []any) Bug {
		_, _, _, name, _ := header[reHeader.SubexpIndex("day")], header[reHeader.SubexpIndex("month")], header[reHeader.SubexpIndex("year")], header[reHeader.SubexpIndex("name")], header[reHeader.SubexpIndex("description")]
		checkrelease(anns, "DSA")
		return Bug{Header: &Header{
			Line:        line,
			Name:        name,
			Description: "",
		}, Annotations: anns}
	}

	bugs, err := parselist(r, parseheader, finish)
	if err != nil {
		return nil, errors.Wrap(err, "parselist")
	}

	return bugs, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L401
func dtsalist(r io.Reader) ([]Bug, error) {
	reHeader := regexp.MustCompile(`^\[(?P<month>[A-Z][a-z]{2,}) (?P<day>\d\d?)(?:st|nd|rd|th), (?P<year>\d{4})\] ` + `(?P<name>DTSA-\d+-\d+)\s+` + `(?P<description>.*?)\s*$`)
	parseheader := func(line string) []string {
		match := reHeader.FindStringSubmatch(line)
		if len(match) == 0 {
			return nil
		}
		return match
	}

	finish := func(header []string, line string, anns []any) Bug {
		_, _, _, name, _ := header[reHeader.SubexpIndex("day")], header[reHeader.SubexpIndex("month")], header[reHeader.SubexpIndex("year")], header[reHeader.SubexpIndex("name")], header[reHeader.SubexpIndex("description")]
		checkrelease(anns, "DTSA")
		return Bug{Header: &Header{
			Line:        line,
			Name:        name,
			Description: "",
		}, Annotations: anns}
	}

	bugs, err := parselist(r, parseheader, finish)
	if err != nil {
		return nil, errors.Wrap(err, "parselist")
	}

	return bugs, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L418
func dlalist(r io.Reader) ([]Bug, error) {
	reHeader := regexp.MustCompile(`^\[(?P<day>\d\d) (?P<month>[A-Z][a-z][a-z]) (?P<year>\d{4})\] ` + `(?P<name>DLA-\d+(?:-\d+)?)\s+` + `(?P<description>.*?)\s*$`)
	parseheader := func(line string) []string {
		match := reHeader.FindStringSubmatch(line)
		if len(match) == 0 {
			return nil
		}
		return match
	}

	finish := func(header []string, line string, anns []any) Bug {
		_, _, _, name, _ := header[reHeader.SubexpIndex("day")], header[reHeader.SubexpIndex("month")], header[reHeader.SubexpIndex("year")], header[reHeader.SubexpIndex("name")], header[reHeader.SubexpIndex("description")]
		checkrelease(anns, "DLA")
		return Bug{Header: &Header{
			Line:        line,
			Name:        name,
			Description: "",
		}, Annotations: anns}
	}

	bugs, err := parselist(r, parseheader, finish)
	if err != nil {
		return nil, errors.Wrap(err, "parselist")
	}

	return bugs, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L378
func checkrelease(anns []any, kind string) {
	for _, ann := range anns {
		if a, ok := ann.(PackageAnnotation); ok && a.Type == "package" && a.Release == "" {
			slog.Warn("release annotation required", slog.String("kind", kind))
		}
	}
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L238
func parselist(r io.Reader, parseheader func(line string) []string, finish func(header []string, line string, anns []any) Bug) ([]Bug, error) {
	var (
		bugs       []Bug
		header     []string
		headerline string
		anns       []any
		anns_types = map[string]struct{}{}
		relpkg     = map[string]map[string]struct{}{}
	)

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		switch {
		case line == "":
		case line[0] == ' ' || line[0] == '\t':
			if len(header) == 0 {
				slog.Warn("header expected", slog.String("line", line))
				break
			}

			ann := annotationdispatcher(line)
			if ann != nil {
				switch a := ann.(type) {
				case FlagAnnotation:
					anns_types[a.Type] = struct{}{}
				case StringAnnotation:
					anns_types[a.Type] = struct{}{}
				case XrefAnnotation:
					anns_types[a.Type] = struct{}{}
				case PackageAnnotation:
					anns_types[a.Type] = struct{}{}
					if a.Type == "package" {
						if _, ok := relpkg[a.Release]; ok {
							if _, ok := relpkg[a.Release][a.Package]; ok {
								slog.Warn("duplicate package annotation", slog.String("line", line))
								ann = nil
							}
						}
						if ann != nil {
							if relpkg[a.Release] == nil {
								relpkg[a.Release] = map[string]struct{}{}
							}
							relpkg[a.Release][a.Package] = struct{}{}
						}
					}
				default:
					return nil, errors.Errorf("unknown type: %T", a)
				}
			}

			if ann != nil {
				anns = append(anns, ann)
			}
		default:
			if len(header) != 0 {
				if keys := slices.Collect(maps.Keys(anns_types)); slices.Contains(keys, "NOT-FOR-US") && slices.Contains(keys, "package") {
					slog.Warn("NOT-FOR-US conflicts with package annotations", slog.String("header", headerline))
				}
				if keys := slices.Collect(maps.Keys(anns_types)); slices.Contains(keys, "REJECTED") && slices.Contains(keys, "package") {
					slog.Warn("REJECTED bug has package annotations", slog.String("header", headerline))
				}
				bugs = append(bugs, finish(header, headerline, anns))

				anns = nil
				anns_types = map[string]struct{}{}
				relpkg = map[string]map[string]struct{}{}
			}
			headerline = line

			header = parseheader(line)
			if len(header) == 0 {
				slog.Warn("malformed header", slog.String("line", line))
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, errors.Wrap(err, "scanner encounter error")
	}

	if len(header) != 0 {
		bugs = append(bugs, finish(header, headerline, anns))
	}

	return bugs, nil
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L116
func annotationdispatcher(line string) any {
	switch {
	case pkgVersionRegexp.MatchString(line):
		groups := pkgVersionRegexp.FindStringSubmatch(line)
		release, pkg, version, inner := groups[pkgVersionRegexp.SubexpIndex("release")], groups[pkgVersionRegexp.SubexpIndex("package")], groups[pkgVersionRegexp.SubexpIndex("version")], groups[pkgVersionRegexp.SubexpIndex("inner")]
		flags := parseinner(inner)

		kind := "fixed"
		if version == "" {
			kind = "unfixed"
		}

		return PackageAnnotation{
			Line:        line,
			Type:        "package",
			Release:     release,
			Package:     pkg,
			Kind:        kind,
			Version:     version,
			Description: "",
			Flags:       flags,
		}
	case pkgPseudoRegexp.MatchString(line):
		groups := pkgPseudoRegexp.FindStringSubmatch(line)
		release, pkg, kind, inner := groups[pkgPseudoRegexp.SubexpIndex("release")], groups[pkgPseudoRegexp.SubexpIndex("package")], groups[pkgPseudoRegexp.SubexpIndex("kind")], groups[pkgPseudoRegexp.SubexpIndex("inner")]

		switch {
		case slices.Contains(pseudoFreeText, kind):
			return PackageAnnotation{
				Line:        line,
				Type:        "package",
				Release:     release,
				Package:     pkg,
				Kind:        kind,
				Version:     "",
				Description: inner,
				Flags:       nil,
			}
		case slices.Contains(pseudoStruct, kind):
			flags := parseinner(inner)
			if kind == "itp" && !slices.ContainsFunc(flags, func(i any) bool { _, ok := i.(PackageBugAnnotation); return ok }) {
				slog.Warn("<itp> needs Debian bug reference", slog.String("line", line))
			}
			return PackageAnnotation{
				Line:        line,
				Type:        "package",
				Release:     release,
				Package:     pkg,
				Kind:        kind,
				Version:     "",
				Description: "",
				Flags:       flags,
			}
		default:
			slog.Warn("invalid pseudo-version", slog.String("kind", kind), slog.String("line", line))
			return nil
		}
	case xrefRegexp.MatchString(line):
		groups := xrefRegexp.FindStringSubmatch(line)
		if x := strings.Fields(strings.TrimSpace(groups[xrefRegexp.SubexpIndex("xref")])); len(x) > 0 {
			return XrefAnnotation{
				Line: line,
				Type: "xref",
				Bugs: x,
			}
		}
		slog.Warn("empty cross-reference", slog.String("line", line))
		return nil
	case flagRegexp.MatchString(line):
		groups := flagRegexp.FindStringSubmatch(line)
		return FlagAnnotation{
			Line: line,
			Type: groups[flagRegexp.SubexpIndex("type")],
		}
	case stringRegexp.MatchString(line):
		groups := stringRegexp.FindStringSubmatch(line)
		return StringAnnotation{
			Line:        line,
			Type:        groups[stringRegexp.SubexpIndex("type")],
			Description: groups[stringRegexp.SubexpIndex("description")],
		}
	default:
		slog.Warn("invalid annotation", slog.String("line", line))
		return nil
	}
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L137
func parseinner(inner string) []any {
	if inner == "" {
		return nil
	}

	var flags []any
	for innerann := range strings.SplitSeq(inner, ";") {
		switch {
		case pkgUrgencyRegexp.MatchString(innerann):
			groups := pkgUrgencyRegexp.FindStringSubmatch(innerann)
			f := groups[pkgUrgencyRegexp.SubexpIndex("flag")]
			if slices.ContainsFunc(flags, func(i any) bool {
				a, ok := i.(PackageUrgencyAnnotation)
				return ok && a.Severity == f
			}) {
				slog.Warn("duplicate urgency", slog.String("field", f), slog.String("inner", inner))
			} else {
				flags = append(flags, PackageUrgencyAnnotation{Severity: f})
			}
		case pkgBugRegexp.MatchString(innerann):
			groups := pkgBugRegexp.FindStringSubmatch(innerann)
			no, err := strconv.Atoi(groups[pkgBugRegexp.SubexpIndex("no")])
			if err != nil {
				slog.Warn("atoi err", slog.Any("err", err))
			}
			if slices.ContainsFunc(flags, func(i any) bool {
				a, ok := i.(PackageBugAnnotation)
				return ok && a.Bug == no
			}) {
				slog.Warn("duplicate bug number", slog.String("number", fmt.Sprintf("%d", no)), slog.String("inner", inner))
			} else {
				flags = append(flags, PackageBugAnnotation{Bug: no})
			}
		default:
			slog.Warn("invalid inner annotation", slog.String("annotation", innerann), slog.String("inner", inner))
		}
	}

	var urgencies []string
	for _, f := range flags {
		if a, ok := f.(PackageUrgencyAnnotation); ok {
			urgencies = append(urgencies, a.Severity)
		}
	}
	if len(urgencies) > 1 {
		slog.Warn("multiple urgencies", slog.String("urgencies", strings.Join(urgencies, ", ")), slog.String("inner", inner))
	}

	return flags
}

func parseConfig(r io.Reader) (archives []string, releases []string, err error) {
	var c config
	if err := json.UnmarshalRead(r, &c); err != nil {
		return nil, nil, errors.Wrap(err, "decode json")
	}

	var others []string
	for codename, d := range c.Distributions {
		if codename == "sid" {
			continue
		}
		if d.Release != "" {
			releases = append(releases, codename)
			continue
		}
		others = append(others, codename)
	}
	slices.SortFunc(releases, func(a, b string) int {
		return cmp.Compare(slices.Index(codenames, a), slices.Index(codenames, b))
	})
	releases = append(releases, "sid")

	for _, codename := range others {
		if !slices.Contains(codenames, codename) {
			continue
		}
		if slices.Index(codenames, codename) > slices.Index(codenames, releases[len(releases)-2]) {
			continue
		}
		archives = append(archives, codename)
	}
	slices.SortFunc(archives, func(a, b string) int {
		return cmp.Compare(slices.Index(codenames, a), slices.Index(codenames, b))
	})

	return archives, releases, nil
}

func (opts *options) fetchSource(codename string, archived bool) (map[string]map[string]map[string]paragraph, error) {
	m := map[string]map[string]map[string]paragraph{
		"stable":   make(map[string]map[string]paragraph),
		"security": make(map[string]map[string]paragraph),
		"backport": make(map[string]map[string]paragraph),
	}

	stableURL := opts.mirror.ReleaseStable
	securityURL := opts.mirror.ReleaseSecurity
	backportURL := opts.mirror.ReleaseBackport
	if archived {
		stableURL = opts.mirror.ArchiveStable
		securityURL = opts.mirror.ArchiveSecurity
		backportURL = opts.mirror.ArchiveBackport
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientHTTPClient(opts.httpClient))

	slog.Info("Fetch Debian stable", slog.String("codename", codename))
	stableDistURL := fmt.Sprintf("%s/dists/%s", stableURL, codename)
	rel, err := opts.fetchRelease(client, stableDistURL, codename, archived)
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range rel.components {
		sources, err := fetchSource(client, stableDistURL, rel, section)
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["stable"][section] = sources
	}

	if codename == "sid" {
		return m, nil
	}

	slog.Info("Fetch Debian security", slog.String("codename", codename))
	securitySuite := fmt.Sprintf("%s/updates", codename)
	if slices.Index(codenames, codename) == -1 || slices.Index(codenames, codename) > slices.Index(codenames, "buster") {
		securitySuite = fmt.Sprintf("%s-security", codename)
	}
	securityDistURL := fmt.Sprintf("%s/dists/%s", securityURL, securitySuite)

	rel, err = opts.fetchRelease(client, securityDistURL, securitySuite, archived)
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range rel.components {
		sources, err := fetchSource(client, securityDistURL, rel, section)
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["security"][filepath.Base(section)] = sources
	}

	slog.Info("Fetch Debian backport", slog.String("codename", codename))
	if slices.Index(codenames, codename) == -1 || slices.Index(codenames, codename) >= slices.Index(codenames, "wheezy") {
		backportURL = stableURL
	}

	backportSuite := fmt.Sprintf("%s-backports", codename)
	backportDistURL := fmt.Sprintf("%s/dists/%s", backportURL, backportSuite)
	rel, err = opts.fetchRelease(client, backportDistURL, backportSuite, archived)
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range rel.components {
		sources, err := fetchSource(client, backportDistURL, rel, section)
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["backport"][section] = sources
	}

	return m, nil
}

// hash names the field of the Release of suite, a path under dists, that the
// Sources of the suite are checked against.
func (opts *options) hash(suite string) string {
	if slices.Contains(opts.sha1Suites, suite) {
		return "SHA1"
	}
	return "SHA256"
}

// release is what the fetcher reads from the Release file of a suite.
type release struct {
	codename string
	label    string
	// validUntil is when the Release stops being good, if it says.
	validUntil    time.Time
	components    []string
	acquireByHash bool
	// hash names the field of the Release that files comes from: SHA256, or
	// SHA1 for a suite of sha1Suites.
	hash string
	// files maps the path of a file, relative to the directory of the
	// Release, to the size and digest the Release gives for it.
	files map[string]checksum
}

type checksum struct {
	size   int64
	digest string
}

// securityLabel is the Label of the Release of a security suite, and of no
// other.
const securityLabel = "Debian-Security"

// digestSizes gives the size in bytes of a digest in each field of a Release
// that Sources are checked against.
var digestSizes = map[string]int{"SHA256": sha256.Size, "SHA1": sha1.Size}

// fetchRelease fetches the Release of suite, its path under dists, from
// distURL, checks it as checkedRelease does, and parses it, taking the
// checksums from the field opts.hash names. The Release must name suite as its
// Codename, have the Label of a security suite exactly when suite is one, and,
// unless the suite is archived, not be past its Valid-Until. A suite whose
// Release the mirror does not have is skipped: the release returned lists no
// component.
func (opts *options) fetchRelease(c *utilhttp.Client, distURL, suite string, archived bool) (release, error) {
	bs, found, err := opts.checkedRelease(c, distURL, suite)
	if err != nil {
		return release{}, errors.Wrapf(err, "check %s/Release", distURL)
	}
	if !found {
		return release{}, nil
	}

	rel, err := parseRelease(bytes.NewReader(bs), opts.hash(suite))
	if err != nil {
		return release{}, errors.Wrapf(err, "parse %s/Release", distURL)
	}

	// A security suite up to buster, <codename>/updates, has the codename
	// alone as its Codename, as the stable suite of the codename has. Its
	// Label, Debian-Security, as unattended-upgrades tells security updates
	// by, tells their Release files apart.
	if codename := strings.TrimSuffix(suite, "/updates"); rel.codename != codename {
		return release{}, errors.Errorf("unexpected Codename of %s/Release. expected: %q, actual: %q", distURL, codename, rel.codename)
	}
	switch security := strings.HasSuffix(suite, "/updates") || strings.HasSuffix(suite, "-security"); {
	case security && rel.label != securityLabel:
		return release{}, errors.Errorf("unexpected Label of %s/Release. expected: %q, actual: %q", distURL, securityLabel, rel.label)
	case !security && rel.label == securityLabel:
		return release{}, errors.Errorf("unexpected Label of %s/Release. expected: %s, actual: %q", distURL, fmt.Sprintf("other than %q", securityLabel), rel.label)
	}
	// The Valid-Until of an archived suite passed long ago.
	if !archived && !rel.validUntil.IsZero() && !opts.now.Before(rel.validUntil) {
		return release{}, errors.Errorf("unexpected Valid-Until of %s/Release. expected: %s, actual: %q", distURL, fmt.Sprintf("later than %s", opts.now.UTC().Format(time.RFC1123)), rel.validUntil.UTC().Format(time.RFC1123))
	}

	return rel, nil
}

// checkedRelease fetches the Release of suite, its path under dists, from
// distURL and returns its text once checked: against the SHA256
// opts.pinnedReleases gives for the suite, or else against its signature by a
// key of opts.keyring, from InRelease where the mirror has it and from
// Release.gpg where it has only Release. A suite whose Release the mirror does
// not have is reported as not found.
func (opts *options) checkedRelease(c *utilhttp.Client, distURL, suite string) ([]byte, bool, error) {
	if sum, ok := opts.pinnedReleases[suite]; ok {
		bs, found, err := getRelease(c, distURL)
		if err != nil || !found {
			return nil, found, err
		}
		if digest := fmt.Sprintf("%x", sha256.Sum256(bs)); digest != sum {
			return nil, false, errors.Errorf("unexpected SHA256. expected: %q, actual: %q", sum, digest)
		}
		return bs, true, nil
	}

	bs, status, err := get(c, fmt.Sprintf("%s/InRelease", distURL))
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusOK {
		text, err := verifyInRelease(opts.keyring, bs)
		if err != nil {
			return nil, false, errors.Wrap(err, "verify InRelease")
		}
		return text, true, nil
	}

	bs, found, err := getRelease(c, distURL)
	if err != nil || !found {
		return nil, found, err
	}
	sigs, status, err := get(c, fmt.Sprintf("%s/Release.gpg", distURL))
	if err != nil {
		return nil, false, err
	}
	if status != http.StatusOK {
		return nil, false, errors.Errorf("no signature: no InRelease, and Release.gpg answered with status code %d", status)
	}
	if err := verifyRelease(opts.keyring, bs, sigs); err != nil {
		return nil, false, errors.Wrap(err, "verify Release.gpg")
	}
	return bs, true, nil
}

// getRelease fetches the Release at distURL. A response other than 200 is a
// suite the mirror does not have, which is reported as not found, with a
// warning.
func getRelease(c *utilhttp.Client, distURL string) ([]byte, bool, error) {
	u := fmt.Sprintf("%s/Release", distURL)
	bs, status, err := get(c, u)
	if err != nil {
		return nil, false, err
	}
	if status != http.StatusOK {
		slog.Warn("fetch error", slog.String("url", u), slog.Any("err", errors.Errorf("error response with status code %d", status)))
		return nil, false, nil
	}
	return bs, true, nil
}

// get fetches u, returning the status code of the response, and its body if
// that is 200.
func get(c *utilhttp.Client, u string) ([]byte, int, error) {
	resp, err := c.Get(u)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "get %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, resp.StatusCode, nil
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, errors.Wrapf(err, "read %s", u)
	}
	return bs, resp.StatusCode, nil
}

// verifyInRelease checks the signature of the clearsigned InRelease bs against
// keyring and returns the text it signs, which is all that is read of it.
func verifyInRelease(keyring openpgp.KeyRing, bs []byte) ([]byte, error) {
	b, _ := clearsign.Decode(bs)
	if b == nil {
		return nil, errors.New("no clearsigned message")
	}
	if _, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(b.Bytes), b.ArmoredSignature.Body, nil); err != nil {
		return nil, errors.Wrap(err, "verify signature")
	}
	return b.Plaintext, nil
}

// verifyRelease checks the detached signatures sigs, a Release.gpg, over the
// Release bs against keyring. A Release.gpg can hold more than one armored
// block, the stable release key's signature appended to the archive key's, so
// the signatures of every block are read.
func verifyRelease(keyring openpgp.KeyRing, bs, sigs []byte) error {
	const begin = "-----BEGIN PGP SIGNATURE-----"

	blocks := bytes.Split(sigs, []byte(begin))[1:]
	if len(blocks) == 0 {
		return errors.New("no armored signature")
	}
	rs := make([]io.Reader, 0, len(blocks))
	for _, blk := range blocks {
		b, err := armor.Decode(bytes.NewReader(append([]byte(begin), blk...)))
		if err != nil {
			return errors.Wrap(err, "decode armor")
		}
		rs = append(rs, b.Body)
	}
	if _, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(bs), io.MultiReader(rs...), nil); err != nil {
		return errors.Wrap(err, "verify signature")
	}
	return nil
}

// readKeyRing reads binary OpenPGP keyrings into one.
func readKeyRing(keyrings ...[]byte) (openpgp.EntityList, error) {
	var el openpgp.EntityList
	for _, bs := range keyrings {
		l, err := openpgp.ReadKeyRing(bytes.NewReader(bs))
		if err != nil {
			return nil, errors.Wrap(err, "read keyring")
		}
		el = append(el, l...)
	}
	return el, nil
}

// parseRelease reads a Release, a deb822 file of one paragraph, taking the
// checksums from its field hash.
func parseRelease(rd io.Reader, hash string) (release, error) {
	ps, err := parseDeb822(rd)
	if err != nil {
		return release{}, errors.Wrap(err, "parse deb822")
	}
	if len(ps) != 1 {
		return release{}, errors.Errorf("unexpected number of paragraphs. expected: %d, actual: %d", 1, len(ps))
	}
	p := ps[0]

	field, _ := p.field(hash)
	sums, err := parseChecksums(field, hash)
	if err != nil {
		return release{}, errors.Wrapf(err, "parse %s", hash)
	}

	var validUntil time.Time
	if v, _ := p.field("Valid-Until"); v != "" {
		t, err := time.Parse(time.RFC1123, v)
		if err != nil {
			return release{}, errors.Wrap(err, "parse Valid-Until")
		}
		validUntil = t
	}

	codename, _ := p.field("Codename")
	label, _ := p.field("Label")
	components, _ := p.field("Components")
	acquireByHash, _ := p.field("Acquire-By-Hash")

	return release{
		codename:      codename,
		label:         label,
		validUntil:    validUntil,
		components:    strings.Fields(components),
		acquireByHash: acquireByHash == "yes",
		hash:          hash,
		files:         sums,
	}, nil
}

// parseChecksums reads the value of the field hash of a Release, such as
// SHA256: a multiline field whose first line is empty, and each line after it
// a file's digest, size and path.
func parseChecksums(field, hash string) (map[string]checksum, error) {
	lines := strings.Split(field, "\n")
	if lines[0] != "" {
		return nil, errors.Errorf("unexpected first line. expected: %q, actual: %q", "", lines[0])
	}

	m := make(map[string]checksum, len(lines)-1)
	for _, line := range lines[1:] {
		entry := strings.Fields(line)
		if len(entry) != 3 {
			return nil, errors.Errorf("unexpected line. expected: %s, actual: %q", "<digest> <size> <path>", line)
		}
		digest, size, p := strings.ToLower(entry[0]), entry[1], entry[2]
		if bs, err := hex.DecodeString(digest); err != nil || len(bs) != digestSizes[hash] {
			return nil, errors.Errorf("unexpected %s of %s. expected: %s, actual: %q", hash, p, fmt.Sprintf("%d hex digits", 2*digestSizes[hash]), digest)
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil || n < 0 {
			return nil, errors.Errorf("unexpected size of %s. expected: %s, actual: %q", p, "a non-negative integer", size)
		}
		m[p] = checksum{size: n, digest: digest}
	}

	return m, nil
}

// fetchSource fetches the Sources of section in the suite at distURL, in the
// first compression rel lists that the mirror serves, and parses it once it
// has the size and digest rel gives. Where rel says the suite can be acquired
// by hash, the copy named by the digest is asked for first: it cannot be an
// older or newer file than the one rel describes, as the plain path can while
// the mirror is being updated.
func fetchSource(c *utilhttp.Client, distURL string, rel release, section string) (map[string]paragraph, error) {
	var listed bool
	for _, compress := range []string{"gz", "xz", "bz2"} {
		p := fmt.Sprintf("%s/source/Sources.%s", path.Base(section), compress)
		sum, ok := rel.files[p]
		if !ok {
			continue
		}
		listed = true

		urls := make([]string, 0, 2)
		if rel.acquireByHash {
			urls = append(urls, fmt.Sprintf("%s/%s/by-hash/%s/%s", distURL, path.Dir(p), rel.hash, sum.digest))
		}
		urls = append(urls, fmt.Sprintf("%s/%s", distURL, p))

		for _, u := range urls {
			bs, found, err := fetchFile(c, u, rel.hash, sum)
			if err != nil {
				return nil, errors.Wrapf(err, "fetch %s", u)
			}
			if !found {
				continue
			}

			sources, err := parseCompressedSource(bs, compress)
			if err != nil {
				return nil, errors.Wrapf(err, "parse %s", u)
			}
			return sources, nil
		}
	}

	if !listed {
		return nil, errors.Errorf("no %s of %s/source/Sources.(gz|xz|bz2) in %s/Release", rel.hash, path.Base(section), distURL)
	}
	return nil, errors.Errorf("%s/%s/source/Sources.(gz|xz|bz2) not found", distURL, path.Base(section))
}

// fetchFile fetches u and returns it if it has the size of sum and its digest
// by hash. A response other than 200 means the mirror does not have the file
// there, so it reports nothing found for the caller to try elsewhere; a
// request that fails, or a file that does not match sum, is an error.
func fetchFile(c *utilhttp.Client, u, hash string, sum checksum) ([]byte, bool, error) {
	resp, err := c.Get(u)
	if err != nil {
		return nil, false, errors.Wrap(err, "get")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, false, nil
	}

	// Reading one byte past the size sum gives tells a longer file, and goes
	// no further into it.
	bs, err := io.ReadAll(io.LimitReader(resp.Body, sum.size+1))
	if err != nil {
		return nil, false, errors.Wrap(err, "read body")
	}
	switch n := int64(len(bs)); {
	case n > sum.size:
		return nil, false, errors.Errorf("unexpected size. expected: %d, actual: more than %d", sum.size, sum.size)
	case n < sum.size:
		return nil, false, errors.Errorf("unexpected size. expected: %d, actual: %d", sum.size, n)
	}
	var digest string
	switch hash {
	case "SHA256":
		digest = fmt.Sprintf("%x", sha256.Sum256(bs))
	case "SHA1":
		digest = fmt.Sprintf("%x", sha1.Sum(bs))
	default:
		return nil, false, errors.Errorf("unexpected hash. expected: %q, actual: %q", []string{"SHA256", "SHA1"}, hash)
	}
	if digest != sum.digest {
		return nil, false, errors.Errorf("unexpected %s. expected: %q, actual: %q", hash, sum.digest, digest)
	}

	return bs, true, nil
}

func parseCompressedSource(bs []byte, compress string) (map[string]paragraph, error) {
	var r io.Reader
	switch compress {
	case "gz":
		gr, err := gzip.NewReader(bytes.NewReader(bs))
		if err != nil {
			return nil, errors.Wrap(err, "create gzip reader")
		}
		defer gr.Close()
		r = gr
	case "xz":
		xr, err := xz.NewReader(bytes.NewReader(bs))
		if err != nil {
			return nil, errors.Wrap(err, "create xz reader")
		}
		r = xr
	case "bz2":
		r = bzip2.NewReader(bytes.NewReader(bs))
	default:
		return nil, errors.Errorf("unexpected compress format. expected: %q, actual: %q", []string{"gz", "xz", "bz2"}, compress)
	}

	sources, err := parseSource(r)
	if err != nil {
		return nil, errors.Wrap(err, "parse source")
	}

	return sources, nil
}

// parseSource reads the paragraphs of a Sources file, a deb822 file, by the
// source package each describes, which its Package field names.
func parseSource(r io.Reader) (map[string]paragraph, error) {
	ps, err := parseDeb822(r)
	if err != nil {
		return nil, errors.Wrap(err, "parse deb822")
	}

	m := make(map[string]paragraph, len(ps))
	for _, p := range ps {
		name, _ := p.field("Package")
		if name == "" {
			slog.Warn("Package field not found")
			continue
		}
		m[name] = p
	}

	return m, nil
}
