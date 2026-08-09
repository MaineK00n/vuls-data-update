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
// under advisories/: their sections are prose bundles of dozens of releases,
// not release sections, so no detections are derived from them.
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
	// and only names releaseCriterions maps to a CPE yield a condition
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
		cs, err := releaseCriterions(s.Name)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "release criterions. root: %s", rootID)
		}
		if len(cs) == 0 {
			continue
		}
		tag := segmentTypes.DetectionTag(s.Name)
		// combined pages may repeat a section name, e.g. "Safari 11.0.2"
		// twice; the same name maps to the same criterions, so keep the first
		if !slices.ContainsFunc(conditions, func(c conditionTypes.Condition) bool { return c.Tag == tag }) {
			conditions = append(conditions, conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cs,
				},
				Tag: tag,
			})
		}
		for _, c := range sectionCVEs {
			if !slices.Contains(tagsByCVE[c], tag) {
				tagsByCVE[c] = append(tagsByCVE[c], tag)
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
// outside these patterns (applications, firmware, "Security Update
// YYYY-NNN", ...) yield no detection on purpose: the advisory and
// vulnerability contents are still extracted, and widening the detection
// scope is a matter of adding patterns here.
//
// Submatch 1 is the version; submatch 2 is the Rapid Security Response
// letter (" (a)" in "iOS 16.5.1 (a)"), which Apple appends to the base OS
// version it patches.
var releasePatterns = []struct {
	re  *regexp.Regexp
	cpe string
}{
	{regexp.MustCompile(`^macOS(?: (?:Sierra|High Sierra|Mojave|Catalina|Big Sur|Monterey|Ventura|Sonoma|Sequoia|Tahoe))? v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^(?:Mac )?OS X(?: (?:Lion|Mountain Lion|Mavericks|Yosemite|El Capitan))? v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^iOS v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^iPadOS v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^(?:watchOS|Watch OS) v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:watchos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^tvOS v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^visionOS v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:o:apple:visionos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^Safari v?([0-9][0-9.]*[0-9]|[0-9])( \([a-z]\))?$`), "cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*"},
}

// releaseNameSeparators split a combined release name such as
// "macOS High Sierra 10.13.2, Security Update 2017-002 Sierra, and Security
// Update 2017-005 El Capitan" or "iOS 26.6 and iPadOS 26.6" into its parts.
var releaseNameSeparators = regexp.MustCompile(`, and |; and |, |; | and | / `)

// unknownMacOSReleasePattern matches the shape of a macOS OS release —
// "macOS <Marketing Name> <version>", version closing the name — so that a
// marketing name missing from releasePatterns fails loudly instead of
// silently losing its detections when Apple ships the release after Tahoe.
// macOS is the only family whose enumeration can go stale: the OS X names
// are historical and closed, and the other families do not carry marketing
// names. "macOS Server <version>" is the one known lookalike of this shape
// and is excluded where the pattern is applied.
var unknownMacOSReleasePattern = regexp.MustCompile(`^macOS (?:[A-Z][A-Za-z]+ )+([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`)

// releaseCriterions maps a release name to CPE criterions, one per part of
// the name that names an OS release or Safari: the release fixes the listed
// vulnerabilities, so versions below it are vulnerable.
func releaseCriterions(name string) ([]criterionTypes.Criterion, error) {
	var cs []criterionTypes.Criterion
	for _, part := range releaseNameSeparators.Split(name, -1) {
		// a trailing asterisk is a footnote marker, e.g. "Safari 14.1*"
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), "*"))
		var matched bool
		for _, p := range releasePatterns {
			m := p.re.FindStringSubmatch(part)
			if m == nil {
				continue
			}
			matched = true
			cs = append(cs, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					CPE:        ccTypes.CPE(p.cpe),
					Range: func() *ccRangeTypes.Range {
						// a Rapid Security Response patches vulnerabilities
						// present in the base version it suffixes, so the
						// base itself is vulnerable: the range is inclusive.
						// The suffixed form is not usable as a comparison
						// bound (the version comparator cannot parse it) but
						// is kept verbatim in Fixed
						if m[2] != "" {
							return &ccRangeTypes.Range{
								Type:      ccRangeTypes.RangeTypeVersion,
								LessEqual: m[1],
							}
						}
						return &ccRangeTypes.Range{
							Type:     ccRangeTypes.RangeTypeVersion,
							LessThan: m[1],
						}
					}(),
					Fixed: []string{m[1] + m[2]},
				},
			})
			break
		}
		if !matched && unknownMacOSReleasePattern.MatchString(part) && !strings.HasPrefix(part, "macOS Server ") {
			return nil, errors.Errorf("unexpected macOS marketing name. expected: enumerated in releasePatterns, actual: %q", part)
		}
	}
	return cs, nil
}
