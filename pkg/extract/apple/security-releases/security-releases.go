package securityreleases

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	securityreleases "github.com/MaineK00n/vuls-data-update/pkg/fetch/apple/security-releases"
)

// vulnerabilityIDPattern matches CVE IDs and their pre-2005 candidate form
// (CAN-), which shares the number space with CVE.
var vulnerabilityIDPattern = regexp.MustCompile(`(CVE|CAN)-[0-9]{4}-[0-9]{4,}`)

// inlineAdvisoryPageIDs are the pre-2005 archive pages the fetch stage stores
// under advisories/: bundles of dozens of releases whose whole-bold headings
// flatten into entry components, release headings ("Security Update
// 2004-12-02") side by side with the components fixed inside them ("Apache").
// Deriving detections would take a positional reconstruction of that
// hierarchy and recover only about a dozen plain "Mac OS X 10.x.y" releases
// of the CAN era, so these pages deliberately yield vulnerabilities but no
// detections.
var inlineAdvisoryPageIDs = []string{"101682", "104191"}

// trailingDatePattern matches the release date at the end of a list-format
// row text, e.g. "- Mac OS X v10.4 - v10.4.5 - 03 Apr 2006".
var trailingDatePattern = regexp.MustCompile(`[0-9]{1,2} [A-Z][a-z]{2,8} [0-9]{4}$`)

type options struct {
	dir string
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

// release is a row of a security releases list page, joined to advisories by
// the article ID the row links to.
type release struct {
	row  securityreleases.Release
	path string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "apple", "security-releases"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Apple Security Releases")

	releases, err := readLists(args)
	if err != nil {
		return errors.Wrap(err, "read lists")
	}

	if err := filepath.WalkDir(filepath.Join(args, "advisories"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(p) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched securityreleases.Advisory
		if err := r.Read(p, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", p)
		}

		rs := releases[strings.TrimSuffix(filepath.Base(p), ".json")]
		raws := r.Paths()
		for _, r := range rs {
			if !slices.Contains(raws, r.path) {
				raws = append(raws, r.path)
			}
		}

		extracted, err := extract(fetched, rs, raws)
		if err != nil {
			return errors.Wrapf(err, "extract %s", p)
		}

		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", filepath.Join(args, "advisories"))
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.AppleSecurityReleases,
		Name: new("Apple Security Releases"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// readLists reads the security releases list pages and indexes their rows by
// the article ID each row links to, which is also the file name the fetch
// stage stores the linked advisory under.
func readLists(args string) (map[string][]release, error) {
	releases := make(map[string][]release)
	if err := filepath.WalkDir(filepath.Join(args, "lists"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(p) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched securityreleases.List
		if err := r.Read(p, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", p)
		}
		if len(r.Paths()) != 1 {
			return errors.Errorf("unexpected number of read paths. expected: %d, actual: %d", 1, len(r.Paths()))
		}

		for _, row := range fetched.Releases {
			if row.URL == "" {
				continue
			}
			u, err := url.Parse(row.URL)
			if err != nil {
				return errors.Wrapf(err, "parse %s", row.URL)
			}
			releases[path.Base(u.Path)] = append(releases[path.Base(u.Path)], release{row: row, path: r.Paths()[0]})
		}

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", filepath.Join(args, "lists"))
	}
	return releases, nil
}

func extract(fetched securityreleases.Advisory, releases []release, raws []string) (dataTypes.Data, error) {
	// the root ID is the raw advisory's ID as fetched, so data/<root>.json
	// always sits next to the raw advisories/<id>.json of the same name.
	// Resolving legacy HT/TA IDs to the canonical numeric form is the fetch
	// stage's business, not derived here
	rootID := fetched.ID

	title := fetched.Title
	if title == "" && len(releases) > 0 {
		// pages are sometimes served with an empty <h1>; fall back to the
		// release name the list rows carry
		title = releases[0].row.Name
	}

	// one condition per release section, tagged with the raw section name;
	// the sections of the pre-2005 inline archive pages are not releases,
	// and only names releaseCriterions maps to a CPE yield a condition.
	// macOS is the exception: its criterions come from each entry's
	// "Available for", so a section splits into one condition per distinct
	// field value, tagged with the field
	var conditions []conditionTypes.Condition
	tagsByCVE := make(map[string][]segmentTypes.DetectionTag)
	var cves []string
	for _, s := range fetched.Sections {
		var sectionCVEs []string
		for _, e := range s.Entries {
			// vulnerability references live in IDs; the pre-2005 inline
			// archive pages carry them in prose, which the fetch stage
			// stores in Others
			for _, t := range slices.Concat(e.IDs, e.Others) {
				for _, m := range vulnerabilityIDPattern.FindAllString(t, -1) {
					// CAN- is the pre-2005 candidate form of the same CVE
					// number
					sectionCVEs = append(sectionCVEs, strings.Replace(m, "CAN-", "CVE-", 1))
				}
			}
		}
		slices.Sort(sectionCVEs)
		sectionCVEs = slices.Compact(sectionCVEs)
		cves = append(cves, sectionCVEs...)

		if slices.Contains(inlineAdvisoryPageIDs, rootID) {
			continue
		}
		cs, fixes, err := releaseCriterions(s.Name)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "release criterions. root: %s", rootID)
		}

		add := func(tag segmentTypes.DetectionTag, cs []criterionTypes.Criterion, tagged []string) {
			if len(cs) == 0 {
				return
			}
			// combined pages may repeat a section name, e.g. "Safari 11.0.2"
			// twice; the same name maps to the same criterions, so keep the
			// first
			if !slices.ContainsFunc(conditions, func(c conditionTypes.Condition) bool { return c.Tag == tag }) {
				conditions = append(conditions, conditionTypes.Condition{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: cs,
					},
					Tag: tag,
				})
			}
			for _, c := range tagged {
				if !slices.Contains(tagsByCVE[c], tag) {
					tagsByCVE[c] = append(tagsByCVE[c], tag)
				}
			}
		}

		add(segmentTypes.DetectionTag(s.Name), cs, sectionCVEs)

		// macOS takes its criterions from each entry's "Available for", so a
		// section carrying several distinct fields splits into one condition
		// per field. Entries sharing a field share a condition. The heading
		// is not consulted to decide whether to look: a Supplemental Update
		// heading names no version of its own, yet its entries state the
		// version they are for
		if isMacOSSection(s.Name) {
			for _, e := range s.Entries {
				if len(e.AvailableFor) == 0 {
					continue
				}
				var entryCVEs []string
				for _, t := range slices.Concat(e.IDs, e.Others) {
					for _, m := range vulnerabilityIDPattern.FindAllString(t, -1) {
						entryCVEs = append(entryCVEs, strings.Replace(m, "CAN-", "CVE-", 1))
					}
				}
				slices.Sort(entryCVEs)
				mcs, err := macOSCriterionsFor(e.AvailableFor, fixes)
				if err != nil {
					return dataTypes.Data{}, errors.Wrapf(err, "macOS criterions. root: %s", rootID)
				}
				add(segmentTypes.DetectionTag(strings.Join(e.AvailableFor, ", ")), mcs, slices.Compact(entryCVEs))
			}
		}
	}
	slices.Sort(cves)
	cves = slices.Compact(cves)

	// a lone condition pairs with its vulnerabilities unambiguously; tags
	// are kept only when multiple release sections yield conditions, as on
	// the combined multi-product pages
	if len(conditions) == 1 {
		conditions[0].Tag = ""
		for c, ts := range tagsByCVE {
			if len(ts) > 0 {
				tagsByCVE[c] = []segmentTypes.DetectionTag{""}
			}
		}
	}

	segments := func(tags []segmentTypes.DetectionTag) []segmentTypes.Segment {
		ss := make([]segmentTypes.Segment, 0, len(tags))
		for _, t := range tags {
			ss = append(ss, segmentTypes.Segment{Ecosystem: ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeCPE), Tag: t})
		}
		return ss
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(rootID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:         advisoryContentTypes.AdvisoryID(rootID),
				Title:      title,
				References: []referenceTypes.Reference{{Source: "support.apple.com", URL: fetched.URL}},
				Published:  published(fetched, releases),
			},
			Segments: segments(func() []segmentTypes.DetectionTag {
				ts := make([]segmentTypes.DetectionTag, 0, len(conditions))
				for _, c := range conditions {
					ts = append(ts, c.Tag)
				}
				return ts
			}()),
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(cves))
			for _, c := range cves {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: vulnerabilityContentTypes.VulnerabilityID(c),
						References: []referenceTypes.Reference{{
							Source: "support.apple.com",
							URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", c),
						}},
					},
					Segments: segments(tagsByCVE[c]),
				})
			}
			return vs
		}(),
		Detections: func() []detectionTypes.Detection {
			if len(conditions) == 0 {
				return nil
			}
			return []detectionTypes.Detection{{
				Ecosystem:  ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeCPE),
				Conditions: conditions,
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.AppleSecurityReleases,
			Raws: raws,
		},
	}, nil
}

func published(fetched securityreleases.Advisory, releases []release) *time.Time {
	for _, s := range fetched.Sections {
		for _, e := range s.Entries {
			for _, n := range e.Notes {
				if v, ok := strings.CutPrefix(n, "Released "); ok {
					if t := utiltime.Parse([]string{"January 2, 2006"}, v); t != nil {
						return t
					}
				}
			}
		}
	}
	for _, r := range releases {
		if t := parseDate(r.row.ReleaseDate); t != nil {
			return t
		}
		// list-format rows keep the date at the end of the unparsed row text
		if t := parseDate(trailingDatePattern.FindString(r.row.Text)); t != nil {
			return t
		}
	}
	return nil
}

// parseDate parses the release date column formats: "27 Jul 2026",
// "26 Sept 2013" (a 4-letter abbreviation Go's "Jan" layout does not accept)
// and the occasional full month name.
func parseDate(v string) *time.Time {
	if t := utiltime.Parse([]string{"2 Jan 2006", "2 January 2006"}, v); t != nil {
		return t
	}
	return utiltime.Parse([]string{"2 Jan 2006"}, strings.ReplaceAll(v, "Sept ", "Sep "))
}

// releasePatterns positively matches the release names that map to a CPE:
// the OS families and Safari. The marketing names are enumerated so that
// lookalikes such as "OS X NTP Security Update 1.0" or "macOS Server 5.2"
// never match, and the version must close the name so that derived releases
// such as "macOS Catalina 10.15.7 Supplemental Update" fall through. Names
// outside these patterns yield no detection on purpose — applications
// ("iTunes 12.9 for Windows"), firmware, the version-less "Security Update
// YYYY-NNN" releases (installing one does not change the OS version, so no
// version range can express it), and the pre-2015 spellings of current
// products ("Apple TV 7.2", "iOS 4.3.5 Software Update") — the advisory and
// vulnerability contents are still extracted, and widening the detection
// scope is a matter of adding patterns here.
//
// Submatch 1 is the version and submatch 2 the Rapid Security Response
// letter (" (a)" in "iOS 16.5.1 (a)"): the version fragment is
// AppleVersionPattern, so a captured bound is by construction what the
// apple comparator accepts.
// macOSXCPE and macOSCPE are the two products the desktop OS is filed under,
// split at 10.15/11.0 the way NVD splits it.
const (
	macOSXCPE = "cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*"
	macOSCPE  = "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"
)

var releasePatterns = []struct {
	re  *regexp.Regexp
	cpe string
}{
	{regexp.MustCompile(fmt.Sprintf(`^(?:Mac )?OS X(?: (?:Lion|Mountain Lion|Mavericks|Yosemite|El Capitan))? v?%s$`, ccRangeTypes.AppleVersionPattern)), macOSXCPE},
	{regexp.MustCompile(fmt.Sprintf(`^iOS v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(fmt.Sprintf(`^iPadOS v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(fmt.Sprintf(`^(?:watchOS|Watch OS) v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:o:apple:watchos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(fmt.Sprintf(`^tvOS v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(fmt.Sprintf(`^visionOS v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:o:apple:visionos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(fmt.Sprintf(`^Safari v?%s$`, ccRangeTypes.AppleVersionPattern)), "cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*"},
}

// macOSReleasePattern matches a macOS OS release of any marketing name:
// "macOS[ <Name>] <version>[ (<rsr letter>)]", the version closing the
// name. The name is not captured — it carries no information the version
// does not, since both the CPE product and the range's lower bound are
// decided by the major in recordFix — so a new marketing name is a
// no-op here instead of a yearly enumeration update. "macOS Server
// <version>" shares the shape and is skipped by recordFix on its
// major.
var macOSReleasePattern = regexp.MustCompile(fmt.Sprintf(`^macOS(?: [A-Z][A-Za-z]+)* v?%s$`, ccRangeTypes.AppleVersionPattern))

// macOSSectionPattern matches a heading that names a macOS release, with or
// without a version and with or without the "Supplemental Update" suffix the
// combined pages carry. Only under such a heading does "Available for" name
// the affected systems: under an application heading — "Xcode 16", "Safari
// 17.5", "Java for Mac OS X 10.6 Update 5" — the same field names what the
// application runs on, which is the requirement to install it and not a
// statement that the system is vulnerable.
//
// "OS X Server v4.1" has the shape of a release and is excluded by name: the
// server edition is a product of its own, its versions are not macOS
// versions, and its field states what it runs on like any other application.
var (
	macOSSectionPattern = regexp.MustCompile(`^(?:macOS|(?:Mac )?OS X)(?: [A-Z][A-Za-z]+)*(?: v?\d[\d.]*)?(?: \(\w\))?(?: (?:Supplemental )?Update(?: \d+)?)?$`)
)

// isMacOSSection reports whether a heading names a macOS release rather than
// an application that runs on one. The server edition has the same shape as a
// release — "OS X Server v4.1" — and is excluded by the word wherever it sits,
// since it also sits in the middle ("OS X Lion Server v10.7.3"), and no macOS
// release is named with it.
func isMacOSSection(name string) bool {
	for _, part := range releaseNameSeparators.Split(name, -1) {
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), "*"))
		if macOSSectionPattern.MatchString(part) && !serverWordPattern.MatchString(part) {
			return true
		}
	}
	return false
}

// osFamilyPattern matches the shape of an OS-family release this extractor
// does not know — a future "homeOS 1.0" — so that a family Apple adds next
// to visionOS fails loudly instead of silently losing its detections, the
// same treatment an unexpected macOS major gets. The historical spellings
// ("Mac OS X v10.4", "OS X Server 3.0") have a different shape and do not
// reach it; the known families are matched by releasePatterns first.
var osFamilyPattern = regexp.MustCompile(fmt.Sprintf(`^[A-Za-z]+OS(?: [A-Z][A-Za-z]+)* v?%s$`, ccRangeTypes.AppleVersionPattern))

// releaseNameSeparators split a combined release name such as
// "macOS High Sierra 10.13.2, Security Update 2017-002 Sierra, and Security
// Update 2017-005 El Capitan" or "iOS 26.6 and iPadOS 26.6" into its parts.
var releaseNameSeparators = regexp.MustCompile(`, and |; and |, |; | and | / `)

// releaseCriterions maps a release name to CPE criterions, one per part of
// the name that names an OS release or Safari: the release fixes the listed
// vulnerabilities, so versions below it are vulnerable.
func releaseCriterions(name string) ([]criterionTypes.Criterion, map[string]string, error) {
	var cs []criterionTypes.Criterion
	fixes := make(map[string]string)
	for _, part := range releaseNameSeparators.Split(name, -1) {
		// a trailing asterisk is a footnote marker, e.g. "Safari 14.1*"
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), "*"))

		if m := macOSReleasePattern.FindStringSubmatch(part); m != nil {
			// the heading fixes this line; what it affects comes from the
			// entries' "Available for", so record the fix and emit nothing.
			// The Rapid Security Response letter rides along, the comparator
			// understanding it, so a host on the base version sorts below the
			// bound and matches while the responded one does not
			if err := recordFix(fixes, part, m[1], m[2]); err != nil {
				return nil, nil, err
			}
			continue
		}

		var matched bool
		for _, p := range releasePatterns {
			m := p.re.FindStringSubmatch(part)
			if m == nil {
				continue
			}
			matched = true
			// the apple comparator understands the RSR letter, so the fixed
			// version is the exclusive bound verbatim: for "iOS 16.5.1 (a)"
			// the vulnerable base 16.5.1 sorts below the bound and matches,
			// while the patched 16.5.1 (a) does not
			fixed := fmt.Sprintf("%s%s", m[1], m[2])
			// the desktop OS is spelled both ways across the eras — "macOS
			// Sonoma 14.7.5" and "OS X Yosemite v10.10.2" — and both are the
			// same thing to "Available for", so both record a fix here
			// instead of a criterion
			if p.cpe == macOSXCPE {
				if err := recordFix(fixes, part, m[1], m[2]); err != nil {
					return nil, nil, err
				}
				break
			}
			cs = append(cs, releaseCriterion(p.cpe, &ccRangeTypes.Range{
				Type:     ccRangeTypes.RangeTypeApple,
				LessThan: fixed,
			}, fixed))
			break
		}
		if !matched && osFamilyPattern.MatchString(part) {
			return nil, nil, errors.Errorf("unexpected OS family release name. expected: matched by releasePatterns, actual: %q", part)
		}
	}
	return cs, fixes, nil
}

// recordFix notes which macOS line a release name fixes, keyed by the first
// version of that line. A heading may fix several at once — "macOS Catalina
// 10.15.7, Security Update 2020-005 High Sierra, Security Update 2020-005
// Mojave" — though only the parts carrying a version reach here; the rest of
// that page's lines are named in the entries' "Available for", which closes
// them itself.
//
// The 10.x generations and the majors from 11 on are both accepted, a 10.x
// minor playing the part a major plays later. "macOS Server <version>"
// shares the release-name shape and is skipped by the same major check rather
// than by name: its majors are 2 through 5 (discontinued at 5.12), so it
// lands in the default arm; a hypothetical Server 11 would be filed as macOS.
// Any other major — outside 10.0 through 10.15 and 11 or later — is
// unexpected and errors loudly.
func recordFix(fixes map[string]string, part, version, rsr string) error {
	fixed := fmt.Sprintf("%s%s", version, rsr)
	major, rest, _ := strings.Cut(version, ".")
	switch n, err := strconv.Atoi(major); {
	case err != nil:
		return errors.Wrapf(err, "parse major of %q", version)
	case n >= 11:
		fixes[major] = fixed
		return nil
	case n == 10:
		minor, _, _ := strings.Cut(rest, ".")
		// the heading spells the older generations too — "OS X Yosemite
		// v10.10.2" — and they bound an "Available for" the same way, so the
		// accepted minors run from Cheetah rather than from Sierra
		if mn, err := strconv.Atoi(minor); err == nil && mn >= 0 && mn <= 15 {
			fixes[fmt.Sprintf("10.%d", mn)] = fixed
			return nil
		}
		fallthrough
	default:
		if strings.HasPrefix(part, "macOS Server ") {
			return nil
		}
		return errors.Errorf("unexpected macOS major. expected: 10.x or >= 11, actual: %q", part)
	}
}

func releaseCriterion(cpe string, r *ccRangeTypes.Range, fixed string) criterionTypes.Criterion {
	return criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeCPE,
		CPE: &ccTypes.Criterion{
			Vulnerable: true,
			FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
			CPE:        ccTypes.CPE(cpe),
			Range:      r,
			// a page fixing one line can name an older line as affected, and
			// then the version that fixes the older one lives on its own page
			Fixed: func() []string {
				if fixed == "" {
					return nil
				}
				return []string{fixed}
			}(),
		},
	}
}
