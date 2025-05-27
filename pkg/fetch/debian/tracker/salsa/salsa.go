package salsa

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/bzip2"
	"compress/gzip"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/textproto"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
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

	releaseMain     = "http://deb.debian.org/debian"
	releaseSecurity = "http://security.debian.org/debian-security"
	releaseBackport = "http://deb.debian.org/debian"
	archiveMain     = "http://archive.debian.org/debian"
	archiveSecurity = "http://archive.debian.org/debian-security"
	archiveBackport = "http://archive.debian.org/debian-backports"
	codenames       = []string{"hamm", "slink", "potato", "woody", "sarge", "etch", "lenny", "squeeze", "wheezy", "jessie", "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "sid"}
)

type options struct {
	dataURL string
	dir     string
	retry   int
	mirror  Mirror
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
	ReleaseMain     string
	ReleaseSecurity string
	ReleaseBackport string
	ArchiveMain     string
	ArchiveSecurity string
	ArchiveBackport string
}

type mirrorOption Mirror

func (m mirrorOption) apply(opts *options) {
	opts.mirror = Mirror(m)
}

func WithMirror(m Mirror) Option {
	return mirrorOption(m)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "debian", "tracker", "salsa"),
		retry:   3,
		mirror: Mirror{
			ReleaseMain:     releaseMain,
			ReleaseSecurity: releaseSecurity,
			ReleaseBackport: releaseBackport,
			ArchiveMain:     archiveMain,
			ArchiveSecurity: archiveSecurity,
			ArchiveBackport: archiveBackport,
		},
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Debian Security Tracker Salsa repository")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
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
			log.Printf("[INFO] Fetch Package Source")
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
						log.Printf("[INFO] Fetched Debian %s %s %s", codename, repo, section)
						bar := pb.StartNew(len(mmm))
						for name, source := range mmm {
							if err := util.Write(filepath.Join(options.dir, "packages", codename, repo, section, name[:1], fmt.Sprintf("%s.json", name)), source); err != nil {
								return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "packages", codename, repo, section, name[:1], fmt.Sprintf("%s.json", name)))
							}
							bar.Increment()
						}
						bar.Finish()
					}
				}
			}
		case "list":
			switch filepath.Base(d) {
			case "CPE":
				log.Printf("[INFO] Read CPE/list")
				cpes, err := cpelist(tr)
				if err != nil {
					return errors.Wrap(err, "parse CPE/list")
				}

				bar := pb.StartNew(len(cpes))
				for _, cpe := range cpes {
					if err := util.Write(filepath.Join(options.dir, "CPE", cpe.Package[:1], fmt.Sprintf("%s.json", cpe.Package)), cpe); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "CPE", cpe.Package[:1], fmt.Sprintf("%s.json", cpe.Package)))
					}
					bar.Increment()
				}
				bar.Finish()
			case "CVE":
				log.Printf("[INFO] Read CVE/list")
				bugs, err := cvelist(tr)
				if err != nil {
					return errors.Wrap(err, "parse CVE/list")
				}

				bar := pb.StartNew(len(bugs))
				for _, bug := range bugs {
					switch {
					case strings.HasPrefix(bug.Header.Name, "CVE-"):
						y := strings.Split(bug.Header.Name, "-")[1]
						if err := util.Write(filepath.Join(options.dir, "CVE", y, fmt.Sprintf("%s.json", bug.Header.Name)), bug); err != nil {
							return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "CVE", y, fmt.Sprintf("%s.json", bug.Header.Name)))
						}
						bar.Increment()
					case strings.HasPrefix(bug.Header.Name, "TEMP-"):
						if err := util.Write(filepath.Join(options.dir, "CVE", "TEMP", fmt.Sprintf("%s.json", bug.Header.Name)), bug); err != nil {
							return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "CVE", "TEMP", fmt.Sprintf("%s.json", bug.Header.Name)))
						}
						bar.Increment()
					default:
						return errors.Errorf("invalid header name: %q", bug.Header.Name)
					}
				}
				bar.Finish()
			case "DLA":
				log.Printf("[INFO] Read DLA/list")
				bugs, err := dlalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DLA/list")
				}

				bar := pb.StartNew(len(bugs))
				for _, bug := range bugs {
					if err := util.Write(filepath.Join(options.dir, "DLA", fmt.Sprintf("%s.json", bug.Header.Name)), bug); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "DLA", fmt.Sprintf("%s.json", bug.Header.Name)))
					}
					bar.Increment()
				}
				bar.Finish()
			case "DSA":
				log.Printf("[INFO] Read DSA/list")
				bugs, err := dsalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DSA/list")
				}

				bar := pb.StartNew(len(bugs))
				for _, bug := range bugs {
					if err := util.Write(filepath.Join(options.dir, "DSA", fmt.Sprintf("%s.json", bug.Header.Name)), bug); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "DSA", fmt.Sprintf("%s.json", bug.Header.Name)))
					}
					bar.Increment()
				}
				bar.Finish()
			case "DTSA":
				log.Printf("[INFO] Read DTSA/list")
				bugs, err := dtsalist(tr)
				if err != nil {
					return errors.Wrap(err, "parse DTSA/list")
				}

				bar := pb.StartNew(len(bugs))
				for _, bug := range bugs {
					if err := util.Write(filepath.Join(options.dir, "DTSA", fmt.Sprintf("%s.json", bug.Header.Name)), bug); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "DTSA", fmt.Sprintf("%s.json", bug.Header.Name)))
					}
					bar.Increment()
				}
				bar.Finish()
			default:
			}
		default:
		}
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
			log.Printf("[WARN] unexpected format. expected: \"<Package>;<CPE>\", actual: %q", line)
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
				log.Printf("[WARN] missing ')': %q", line)
			}
			if desc[:1] == "[" && desc[len(desc)-1:] != "]" {
				log.Printf("[WARN] missing ']': %q", line)
			}
		}
		return match
	}

	finish := func(header []string, line string, anns []interface{}) Bug {
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

	finish := func(header []string, line string, anns []interface{}) Bug {
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

	finish := func(header []string, line string, anns []interface{}) Bug {
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

	finish := func(header []string, line string, anns []interface{}) Bug {
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
func checkrelease(anns []interface{}, kind string) {
	for _, ann := range anns {
		if a, ok := ann.(PackageAnnotation); ok && a.Type == "package" && a.Release == "" {
			log.Printf("[WARN] release annotation required in %q file", kind)
		}
	}
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L238
func parselist(r io.Reader, parseheader func(line string) []string, finish func(header []string, line string, anns []interface{}) Bug) ([]Bug, error) {
	var (
		bugs       []Bug
		header     []string
		headerline string
		anns       []interface{}
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
				log.Printf("[WARN] header expected: %q", line)
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
								log.Printf("[WARN] duplicate package annotation: %q", line)
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
					log.Printf("[WARN] NOT-FOR-US conflicts with package annotations: %q", headerline)
				}
				if keys := slices.Collect(maps.Keys(anns_types)); slices.Contains(keys, "REJECTED") && slices.Contains(keys, "package") {
					log.Printf("[WARN] REJECTED bug has package annotations: %q", headerline)
				}
				bugs = append(bugs, finish(header, headerline, anns))

				anns = nil
				anns_types = map[string]struct{}{}
				relpkg = map[string]map[string]struct{}{}
			}
			headerline = line

			header = parseheader(line)
			if len(header) == 0 {
				log.Printf("[WARN] malformed header: %q", line)
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
func annotationdispatcher(line string) interface{} {
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
			if kind == "itp" && !slices.ContainsFunc(flags, func(i interface{}) bool { _, ok := i.(PackageBugAnnotation); return ok }) {
				log.Printf("[WARN] <itp> needs Debian bug reference: %q", line)
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
			log.Printf("[WARN] invalid pseudo-version(%q): %q", kind, line)
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
		log.Printf("[WARN] empty cross-reference: %q", line)
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
		log.Printf("[WARN] invalid annotation: %q", line)
		return nil
	}
}

// https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/670f51ade33e395efbee1490eb13893c41830441/lib/python/sectracker/parsers.py#L137
func parseinner(inner string) []interface{} {
	if inner == "" {
		return nil
	}

	var flags []interface{}
	for _, innerann := range strings.Split(inner, ";") {
		switch {
		case pkgUrgencyRegexp.MatchString(innerann):
			groups := pkgUrgencyRegexp.FindStringSubmatch(innerann)
			f := groups[pkgUrgencyRegexp.SubexpIndex("flag")]
			if slices.ContainsFunc(flags, func(i interface{}) bool {
				a, ok := i.(PackageUrgencyAnnotation)
				return ok && a.Severity == f
			}) {
				log.Printf("[WARN] duplicate urgency(%q): %q", f, inner)
			} else {
				flags = append(flags, PackageUrgencyAnnotation{Severity: f})
			}
		case pkgBugRegexp.MatchString(innerann):
			groups := pkgBugRegexp.FindStringSubmatch(innerann)
			no, err := strconv.Atoi(groups[pkgBugRegexp.SubexpIndex("no")])
			if err != nil {
				log.Printf("[WARN] atoi err: %s", err)
			}
			if slices.ContainsFunc(flags, func(i interface{}) bool {
				a, ok := i.(PackageBugAnnotation)
				return ok && a.Bug == no
			}) {
				log.Printf("[WARN] duplicate bug number(%q): %q", no, inner)
			} else {
				flags = append(flags, PackageBugAnnotation{Bug: no})
			}
		default:
			log.Printf("[WARN] invalid inner annotation(%q): %q", innerann, inner)
		}
	}

	var urgencies []string
	for _, f := range flags {
		if a, ok := f.(PackageUrgencyAnnotation); ok {
			urgencies = append(urgencies, a.Severity)
		}
	}
	if len(urgencies) > 1 {
		log.Printf("[WARN] multiple urgencies(%q): %q", strings.Join(urgencies, ", "), inner)
	}

	return flags
}

func parseConfig(r io.Reader) (archives []string, releases []string, err error) {
	var c config
	if err := json.NewDecoder(r).Decode(&c); err != nil {
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

func (opts *options) fetchSource(codename string, archived bool) (map[string]map[string]map[string]textproto.MIMEHeader, error) {
	m := map[string]map[string]map[string]textproto.MIMEHeader{
		"main":     make(map[string]map[string]textproto.MIMEHeader),
		"security": make(map[string]map[string]textproto.MIMEHeader),
		"backport": make(map[string]map[string]textproto.MIMEHeader),
	}

	mainURL := opts.mirror.ReleaseMain
	securityURL := opts.mirror.ReleaseSecurity
	backportURL := opts.mirror.ReleaseBackport
	if archived {
		mainURL = opts.mirror.ArchiveMain
		securityURL = opts.mirror.ArchiveSecurity
		backportURL = opts.mirror.ArchiveBackport
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	log.Printf("Fetch Debian %s main", codename)
	sections, err := fetchRelease(client, fmt.Sprintf("%s/dists/%s/Release", mainURL, codename))
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range sections {
		sources, err := fetchSource(client, fmt.Sprintf("%s/dists/%s/%s/source/Sources", mainURL, codename, section))
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["main"][section] = sources
	}

	if codename == "sid" {
		return m, nil
	}

	log.Printf("Fetch Debian %s security", codename)
	securityDistURL := fmt.Sprintf("%s/dists/%s/updates", securityURL, codename)
	if slices.Index(codenames, codename) == -1 || slices.Index(codenames, codename) > slices.Index(codenames, "buster") {
		securityDistURL = fmt.Sprintf("%s/dists/%s-security", securityURL, codename)
	}

	sections, err = fetchRelease(client, fmt.Sprintf("%s/Release", securityDistURL))
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range sections {
		sources, err := fetchSource(client, fmt.Sprintf("%s/%s/source/Sources", securityDistURL, filepath.Base(section)))
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["security"][filepath.Base(section)] = sources
	}

	log.Printf("Fetch Debian %s backport", codename)
	if slices.Index(codenames, codename) == -1 || slices.Index(codenames, codename) >= slices.Index(codenames, "wheezy") {
		backportURL = mainURL
	}

	sections, err = fetchRelease(client, fmt.Sprintf("%s/dists/%s-backports/Release", backportURL, codename))
	if err != nil {
		return nil, errors.Wrap(err, "fetch release")
	}
	for _, section := range sections {
		sources, err := fetchSource(client, fmt.Sprintf("%s/dists/%s-backports/%s/source/Sources", backportURL, codename, section))
		if err != nil {
			return nil, errors.Wrap(err, "fetch source")
		}

		m["backport"][section] = sources
	}

	return m, nil
}

func fetchRelease(c *utilhttp.Client, releaseURL string) ([]string, error) {
	resp, err := c.Get(releaseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "get %s", releaseURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] fetch %s error: %s", releaseURL, errors.Errorf("error response with status code %d", resp.StatusCode))
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}

	sections, err := parseRelease(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", releaseURL)
	}

	return sections, nil
}

func parseRelease(rd io.Reader) ([]string, error) {
	bs, err := io.ReadAll(rd)
	if err != nil {
		return nil, errors.Wrap(err, "read all response body")
	}

	r := textproto.NewReader(bufio.NewReader(strings.NewReader(fmt.Sprintf("%s\n\n", strings.TrimRight(string(bs), "\n")))))
	header, err := r.ReadMIMEHeader()
	if err != nil {
		return nil, errors.Wrap(err, "read MIME header")
	}
	return strings.Fields(header.Get("Components")), nil
}

func fetchSource(c *utilhttp.Client, sourceURL string) (map[string]textproto.MIMEHeader, error) {
	for _, compress := range []string{"gz", "xz", "bz2"} {
		resp, err := c.Get(fmt.Sprintf("%s.%s", sourceURL, compress))
		if err == nil {
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				continue
			}
			return func() (map[string]textproto.MIMEHeader, error) {
				switch compress {
				case "gz":
					r, err := gzip.NewReader(resp.Body)
					if err != nil {
						return nil, errors.Wrap(err, "create gzip reader")
					}
					defer r.Close()

					sources, err := parseSource(r)
					if err != nil {
						return nil, errors.Wrapf(err, "parse %s.gz", sourceURL)
					}

					return sources, nil
				case "xz":
					r, err := xz.NewReader(resp.Body)
					if err != nil {
						return nil, errors.Wrap(err, "create gzip reader")
					}

					sources, err := parseSource(r)
					if err != nil {
						return nil, errors.Wrapf(err, "parse %s.xz", sourceURL)
					}

					return sources, nil
				case "bz2":
					r := bzip2.NewReader(resp.Body)

					sources, err := parseSource(r)
					if err != nil {
						return nil, errors.Wrapf(err, "parse %s.bz2", sourceURL)
					}

					return sources, nil
				default:
					return nil, errors.Errorf("unexpected compress format. expected: %q, actual: %s", []string{"gz", "xz", "bz2"}, compress)
				}
			}()
		}
	}

	return nil, errors.Errorf("%s.(gz|xz|bz2) not found", sourceURL)
}

func parseSource(r io.Reader) (map[string]textproto.MIMEHeader, error) {
	m := make(map[string]textproto.MIMEHeader)

	s := bufio.NewScanner(r)
	buf := new(bytes.Buffer)
	for s.Scan() {
		line := s.Text()
		if _, err := fmt.Fprintf(buf, "%s\n", line); err != nil {
			return nil, errors.Wrap(err, "write buffer")
		}
		if line != "" {
			continue
		}

		r := textproto.NewReader(bufio.NewReader(buf))
		header, err := r.ReadMIMEHeader()
		if err != nil {
			return nil, errors.Wrap(err, "read MIME header")
		}

		name := header.Get("Package")
		if name == "" {
			log.Printf("[WARN] Package header not found")
			continue
		}
		m[name] = header

		buf.Reset()
	}

	return m, nil
}
