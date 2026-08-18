// Package security extracts the OpenSSH security page.
//
// Its input is raw/, not the page: the page is prose and the conversion to
// records is a separate, model-driven step against the copy the fetcher stores
// under origin/ (see pkg/fetch/openssh/security). What arrives here is
// therefore already segmented into entries with their versions transcribed —
// and, because it was produced by a model rather than a parser, it is checked
// on the way in. A version string that is not an OpenSSH release fails the
// extract instead of being skipped: raw/ is small, hand-reviewable, and
// regenerable, so a bad conversion is worth stopping for.
//
// Detections are CPE-side. OpenSSH is not a distribution package, and the page
// speaks about the upstream release ("9.5p1 to 9.7p1") rather than about
// anything a package manager would report, so a version criterion over a
// binary package would have no name to attach to. The criterion is
// openbsd:openssh, and bounds go out as the page states them, portable suffix
// and all, under the openssh range type.
//
// Which is a range type of its own for two reasons, both about the suffix. The
// general-purpose comparator reads "p1" as a pre-release and orders 9.9p1
// *before* 9.9, inverting every bound this source states. And CPE splits the
// suffix into its own attribute — NVD publishes 9.9p1 as version="9.9",
// update="p1" — so the query side has to be folded back together before it is
// compared, which the range type is what selects. Both are handled in
// pkg/extract/types/.../cpecriterion, the same way pan-os handles its "-hN".
//
// Without that, every portable release of one base collapses onto the base and
// a bound cannot separate them. The bound would have to widen to the whole
// series, which for the six advisories whose fix is itself a portable release
// — 9.9p2, 9.3p2, 7.2p2, 7.1p2, 5.8p2 — means reporting the very release that
// carries the fix as vulnerable.
package security

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
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
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openssh/security"
)

// source is what every reference and remediation this package emits is
// attributed to: all of them are read off the one page.
const source = "openssh.com"

// productCPE is the criterion's CPE. OpenSSH is filed under the openbsd vendor
// in NVD, which is what a query CPE will carry.
const productCPE = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"

// versionPattern is what a version string in raw/ has to look like: a dotted
// release, optionally carrying the portable suffix — "9.9", "9.9p1", "3.7.1p2".
// Every version OpenSSH has shipped fits it.
//
// It is applied strictly. raw/ is model-produced, and the failure this guards
// against is not a malformed release number but a plausible-looking string that
// is not one — a range copied from prose as "prior to 7.6 supporting read-only
// mode", a date read as a version. Those would bind into a CPE and quietly
// match nothing (or, in a bound, degrade the whole range to a non-match), so
// they stop the extract where they can still be fixed at the source.
var versionPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)(p[0-9]+)?$`)

// cveIDPattern is the shape a CVE ID has to have, per the CVE Record Format.
// It is applied for the same reason versionPattern is: an ID that is two IDs
// in one field, or lowercase, or trailing prose, becomes a vulnerability ID
// downstream and joins to nothing, silently.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "openssh", "security"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract OpenSSH Security Advisory")

	// Only raw/ is walked. The tree also holds origin/ -- the stored page the
	// records were converted from -- and the conversion instructions under
	// .claude/, neither of which is input to this step.
	root := filepath.Join(args, "raw")
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched security.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.OpenSSHSecurity,
		Name: new("OpenSSH Security Advisory"),
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

func extract(fetched security.Advisory, raws []string) (dataTypes.Data, error) {
	cl, err := claim(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "claims")
	}

	ds, err := detections(fetched, cl.fixed)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "detections")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
				Title:       fetched.Title,
				Description: fetched.Description,
				Workarounds: func() []remediationTypes.Remediation {
					rs := make([]remediationTypes.Remediation, 0, len(fetched.Mitigations))
					for _, m := range fetched.Mitigations {
						rs = append(rs, remediationTypes.Remediation{
							Source:      source,
							Description: m,
						})
					}
					return rs
				}(),
				References: references(fetched),
				Published:  utiltime.Parse([]string{"2006-01-02"}, fetched.Date),
			},
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(cl.cves))
			for _, c := range cl.cves {
				// The ID and nothing else. Everything this package emits is
				// attributed to the page, so a reference here would have to be
				// one the page carries -- and where it carries one for a CVE it
				// names, that link is already on the advisory. The rest would
				// be built rather than read: a cve.org URL is derivable from
				// the ID and locates nothing, and for an annotated ID the
				// document that named it is recorded where it can be checked,
				// on the annotation in raw/, with the sentence it was read off.
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: vulnerabilityContentTypes.VulnerabilityID(c),
					},
					Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
				})
			}
			return vs
		}(),
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.OpenSSHSecurity,
			Raws: raws,
		},
	}, nil
}

// The Advisory fields an annotation is allowed to be about.
const (
	annotationFieldCVEs  = "cves"
	annotationFieldFixed = "fixed"
)

// claims is what the record asserts about one entry once its annotations are
// folded in: the CVE IDs and fix releases the page states, plus the ones read
// off the documents it links to.
//
// The values and nothing else. Which document an annotated one came from is
// not carried through, because nothing downstream emits it -- and that
// provenance is not lost by dropping it here: it is on the annotation in raw/,
// beside the quote that makes it checkable, which is the only place it can be
// checked at all.
type claims struct {
	cves  []string
	fixed []string
}

// claim folds an advisory's annotations into the fields they are about.
//
// raw/ keeps the two apart so that CVEs and Fixed stay re-derivable from the
// stored <li> alone and an annotation cannot be mistaken for a transcription.
// That distinction has done its work by the time extraction runs, and what is
// wanted here is the union: 49 of the 55 entries name no CVE ID, so honouring
// the separation downstream would mean publishing a source that is joinable
// with NVD for six advisories and opaque for the rest.
//
// Page-stated values come first and annotations are appended, so an annotation
// can only ever add. One that repeats what the entry already says is dropped
// rather than duplicated -- the two agreeing is the expected case for the
// entries that state a fix release and link the release notes that confirm it.
func claim(fetched security.Advisory) (claims, error) {
	c := claims{
		cves:  slices.Clone(fetched.CVEs),
		fixed: slices.Clone(fetched.Fixed),
	}

	for _, a := range fetched.Annotations {
		// Stopped rather than skipped, for the reason the version pattern is:
		// these records are model-produced, and a claim filed under a field
		// name nothing reads would be dropped in silence -- which looks exactly
		// like the source having nothing to say.
		var vs *[]string
		switch a.Field {
		case annotationFieldCVEs:
			vs = &c.cves
		case annotationFieldFixed:
			vs = &c.fixed
		default:
			return claims{}, errors.Errorf("unexpected annotation field. expected: %q, actual: %q", []string{annotationFieldCVEs, annotationFieldFixed}, a.Field)
		}

		// Every annotation carries a value, whether or not it folds in. Without
		// one there is no record: the next pass has only "something here" and
		// re-reads the document to find out what.
		if a.Value == "" {
			return claims{}, errors.Errorf("unexpected annotation. expected: %q, actual: %q", "a value", "none")
		}

		// Read, and what it names is not this entry's. Recorded rather than
		// folded, so that the reading is not made again.
		if a.Inapplicable {
			continue
		}

		// A CVE on an entry that exists to record that no OpenSSH release was
		// ever vulnerable inverts what the entry says. It is also the easiest
		// annotation to reach for wrongly: those entries are the ones carrying
		// kb.cert.org links, and those notes are about SSH at large. The skill
		// warns against it; this is where the warning binds -- and the warning
		// is not that the document must go unread, but that what it names is
		// the protocol's, which is what an inapplicable annotation records.
		if a.Field == annotationFieldCVEs && fetched.Status != security.StatusAffected {
			return claims{}, errors.Errorf("unexpected annotation. expected: %q, actual: %q", fmt.Sprintf("no folded %s annotation on a %s advisory (mark it inapplicable if the source names one that is not this entry's)", annotationFieldCVEs, fetched.Status), fmt.Sprintf("%s=%s", a.Field, a.Value))
		}

		if !slices.Contains(*vs, a.Value) {
			*vs = append(*vs, a.Value)
		}
	}

	// Both sets are checked here rather than at each point of use, because both
	// arrive the same way. A page-stated value and an annotated one are equally
	// model-produced, and the folded set is the last place they are still
	// together -- after this, cves becomes a vulnerability ID and fixed becomes
	// remediation text, neither of which is consulted by Accept, so an
	// unchecked value would not fail to match. It would publish.
	for _, v := range c.cves {
		if !cveIDPattern.MatchString(v) {
			return claims{}, errors.Errorf("unexpected cve id. expected: %q, actual: %q", cveIDPattern.String(), v)
		}
	}
	for _, v := range c.fixed {
		if _, _, err := splitVersion(v); err != nil {
			return claims{}, errors.Wrapf(err, "fixed release %q", v)
		}
	}

	return c, nil
}

// references returns the entry's links, led by the page they were read from so
// that every record points back at its source.
func references(fetched security.Advisory) []referenceTypes.Reference {
	rs := make([]referenceTypes.Reference, 0, 1+len(fetched.References))
	if fetched.Origin.URL != "" {
		rs = append(rs, referenceTypes.Reference{
			Source: source,
			URL:    fetched.Origin.URL,
		})
	}
	for _, r := range fetched.References {
		rs = append(rs, referenceTypes.Reference{
			Source: source,
			URL:    r.URL,
		})
	}
	return rs
}

// detections builds the CPE criteria for one entry.
//
// Two kinds of entry produce none. An unaffected one describes a vulnerability
// that never applied to OpenSSH, so there is nothing to detect -- the record
// exists to carry that statement, which is the advisory. An affected one that
// names no version is dropped with a warning rather than emitted unnarrowed:
// a criterion with neither range nor enumeration accepts every version of
// OpenSSH there has ever been, which as a detection is a false positive on
// every host that runs it.
//
// fixed is passed in rather than read off fetched because it is the folded set
// -- the releases the entry names together with any an annotation adds. It
// arrives checked, by claim, which holds an annotated release to what a release
// has to look like exactly as it holds a transcribed one.
func detections(fetched security.Advisory, fixed []string) ([]detectionTypes.Detection, error) {
	if fetched.Status != security.StatusAffected {
		return nil, nil
	}

	cs := make([]criterionTypes.Criterion, 0, len(fetched.Affected))
	for _, a := range fetched.Affected {
		c, err := criterion(a, fixed)
		if err != nil {
			return nil, errors.Wrapf(err, "criterion for %q", a.Component)
		}
		cs = append(cs, c...)
	}

	// One range stated against several programs is several affected elements
	// -- "ssh(1), sshd(8) in OpenSSH prior to version 9.6" is two -- and since
	// the component does not reach the criterion, they collapse to the same
	// one. Emitting it twice would put a duplicate under the OR.
	slices.SortFunc(cs, criterionTypes.Compare)
	cs = slices.CompactFunc(cs, func(x, y criterionTypes.Criterion) bool {
		return criterionTypes.Compare(x, y) == 0
	})

	if len(cs) == 0 {
		slog.Warn("no affected version stated, no detection emitted", slog.String("id", fetched.ID))
		return nil, nil
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: cs,
			},
		}},
	}}, nil
}

// criterion turns one affected element into criteria: one per bounded range,
// and one more carrying the element's exact versions as enumerated CPEs.
//
// A range and an enumeration never share a criterion. CPEMatches is consulted
// as a fallback for queries the Range rejects, so putting both on one would
// read as "in this range, or else one of these" — a relation this source never
// states. Kept apart, each says only what it is.
//
// Component and Condition do not narrow anything. A criterion selects on CPE
// attributes, and neither which OpenSSH program carries the bug nor whether
// sshd_config enables the feature is answerable from a CPE — a scan reports
// the release, not its configuration. Both stay in the advisory, where a reader
// gets them.
func criterion(a security.Affected, fixed []string) ([]criterionTypes.Criterion, error) {
	var (
		rs   []ccRangeTypes.Range
		cpes []ccTypes.CPE
	)
	for _, v := range a.Versions {
		switch {
		case v.Equal != "":
			c, err := exactCPE(v.Equal)
			if err != nil {
				return nil, errors.Wrapf(err, "exact cpe for %q", v.Equal)
			}
			cpes = append(cpes, c)
		default:
			r, err := versionRange(v)
			if err != nil {
				return nil, errors.Wrap(err, "version range")
			}
			rs = append(rs, r)
		}
	}

	cs := make([]criterionTypes.Criterion, 0, len(rs)+1)
	for _, r := range rs {
		cs = append(cs, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  fixStatus(fixed),
				CPE:        productCPE,
				Range:      &r,
				Fixed:      fixed,
			},
		})
	}
	if len(cpes) > 0 {
		cs = append(cs, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  fixStatus(fixed),
				CPE:        productCPE,
				CPEMatches: cpes,
				Fixed:      fixed,
			},
		})
	}

	return cs, nil
}

// fixStatus reports fixed only when the entry names the release that fixes it.
// Most do not: the page states a fix for roughly two thirds of its entries and
// leaves the rest to the release notes it links, and "unknown" is what that is.
func fixStatus(fixed []string) *fixstatusTypes.FixStatus {
	if len(fixed) == 0 {
		return &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown}
	}
	return &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed, Vendor: source}
}

// versionRange carries each bound through as the page states it, portable
// suffix and all: the openssh range type compares them, and the query side is
// folded back together from CPE's version and update attributes before it gets
// there.
func versionRange(v security.Range) (ccRangeTypes.Range, error) {
	if v.GreaterEqual != "" && v.GreaterThan != "" {
		return ccRangeTypes.Range{}, errors.Errorf("unexpected version range. expected: %q, actual: %q", "at most one lower bound", fmt.Sprintf("ge: %s, gt: %s", v.GreaterEqual, v.GreaterThan))
	}
	if v.LessEqual != "" && v.LessThan != "" {
		return ccRangeTypes.Range{}, errors.Errorf("unexpected version range. expected: %q, actual: %q", "at most one upper bound", fmt.Sprintf("le: %s, lt: %s", v.LessEqual, v.LessThan))
	}

	r := ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeOpenSSH}

	for _, b := range []struct {
		raw string
		set *string
	}{
		{raw: v.GreaterThan, set: &r.GreaterThan},
		{raw: v.GreaterEqual, set: &r.GreaterEqual},
		{raw: v.LessThan, set: &r.LessThan},
		{raw: v.LessEqual, set: &r.LessEqual},
	} {
		if b.raw == "" {
			continue
		}
		// The bound goes out verbatim, so it is checked rather than
		// reconstructed: a string that is not a release would otherwise reach
		// the comparator, where it degrades to a non-match and takes the whole
		// range's meaning with it.
		if _, _, err := splitVersion(b.raw); err != nil {
			return ccRangeTypes.Range{}, errors.Wrapf(err, "split %q", b.raw)
		}
		*b.set = strings.TrimSpace(b.raw)
	}

	if r == (ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeOpenSSH}) {
		return ccRangeTypes.Range{}, errors.Errorf("unexpected version range. expected: %q, actual: %q", "at least one of eq, ge, gt, le, lt", "none set")
	}

	return r, nil
}

// exactCPE binds one stated version into a CPE, putting the portable suffix in
// the update attribute the way NVD does: 3.4p1 is version="3.4", update="p1".
func exactCPE(v string) (ccTypes.CPE, error) {
	base, update, err := splitVersion(v)
	if err != nil {
		return "", errors.Wrapf(err, "split %q", v)
	}
	if update == "" {
		update = "*"
	}

	c := fmt.Sprintf("cpe:2.3:a:openbsd:openssh:%s:%s:*:*:*:*:*:*", base, update)

	// Bound versions never reach a CPE, so this is the one place a version
	// string is bound -- and an unbindable CPE would make Accept error at
	// detect time rather than simply not match.
	if _, err := naming.UnbindFS(c); err != nil {
		return "", errors.Wrapf(err, "unbind %q to WFN", c)
	}

	return ccTypes.CPE(c), nil
}

// splitVersion separates an OpenSSH release into its base version and its
// portable suffix: "9.9p1" -> ("9.9", "p1"), "9.9" -> ("9.9", "").
func splitVersion(v string) (string, string, error) {
	m := versionPattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", "", errors.Errorf("unexpected version. expected: %q, actual: %q", versionPattern.String(), v)
	}
	return m[1], m[2], nil
}
