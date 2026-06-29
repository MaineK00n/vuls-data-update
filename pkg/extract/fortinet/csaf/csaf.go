package csaf

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/fortinet"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
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
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

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
		dir: filepath.Join(util.CacheDir(), "extract", "fortinet", "csaf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Fortinet CSAF")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
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
		var fetched csafTypes.CSAF
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		data, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		y, err := fortinet.YearDir(string(data.ID))
		if err != nil {
			return errors.Wrapf(err, "year dir %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.FortinetCSAF,
		Name: new("Fortinet PSIRT Advisories (CSAF)"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{URL: u}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// productRef is a product_tree node resolved to a CPE plus the version
// expression carried in its branch name (the part after "<product>/").
type productRef struct {
	cpe        string
	versionExp string
}

// cveAcc accumulates the per-CVE fields merged across the multiple CSAF
// vulnerability objects that share a CVE. String slices are deduped on emit.
type cveAcc struct {
	description string
	severity    []severityTypes.Severity
	cwe         []string
	workarounds []string
	references  []string
	criterions  []criterionTypes.Criterion
}

func extract(fetched csafTypes.CSAF, raws []string) (dataTypes.Data, error) {
	id := fetched.Document.Tracking.ID
	if id == "" {
		return dataTypes.Data{}, errors.New("document.tracking.id is empty")
	}

	refMap := buildProductRefs(fetched.ProductTree.Branches)

	// Fortinet splits one logical CVE across several CSAF vulnerability objects
	// (one per product family), each repeating the scores/notes. Merge them by
	// CVE so each CVE yields a single vulnerability record and condition.
	accs := make(map[string]*cveAcc)
	for _, v := range fetched.Vulnerabilities {
		if v.CVE == "" {
			return dataTypes.Data{}, errors.Errorf("vulnerability without cve in advisory %s", id)
		}

		a, ok := accs[v.CVE]
		if !ok {
			a = &cveAcc{}
			accs[v.CVE] = a
		}

		if a.description == "" {
			a.description = noteText(v.Notes, "Summary")
		}
		sev, err := vulnSeverity(v)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "severity for advisory %s, %s", id, v.CVE)
		}
		a.severity = append(a.severity, sev...)
		if v.CWE != nil && v.CWE.ID != "" {
			a.cwe = append(a.cwe, v.CWE.ID)
		}
		if w := noteText(v.Notes, "Workarounds"); !placeholderNote(w) {
			a.workarounds = append(a.workarounds, w)
		}
		for _, r := range v.References {
			// A single reference.url sometimes packs several URLs separated by
			// CRLF/whitespace; emit one Reference per URL.
			a.references = append(a.references, strings.Fields(r.URL)...)
		}
		for _, pid := range v.ProductStatus.KnownAffected {
			cn, err := toCriterion(string(pid), refMap)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "resolve known_affected %q (advisory %s, %s)", string(pid), id, v.CVE)
			}
			a.criterions = append(a.criterions, cn)
		}
	}

	var (
		vulns      []vulnerabilityTypes.Vulnerability
		conditions []conditionTypes.Condition
		segments   []segmentTypes.Segment
	)
	for cve, a := range accs {
		seg := segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: segmentTypes.DetectionTag(cve)}

		// Only carry the CVE-tagged segment when it has a matching detection
		// condition. A CVE with no known_affected (e.g. known_not_affected
		// only) otherwise leaves a dangling segment tag with no condition or
		// advisory segment, producing an internally inconsistent dataset.
		var vsegs []segmentTypes.Segment
		if len(a.criterions) > 0 {
			segments = append(segments, seg)
			vsegs = []segmentTypes.Segment{seg}
			conditions = append(conditions, conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: a.criterions,
				},
				Tag: segmentTypes.DetectionTag(cve),
			})
		}

		vulns = append(vulns, vulnerabilityTypes.Vulnerability{
			Content: vulnerabilityContentTypes.Content{
				ID: vulnerabilityContentTypes.VulnerabilityID(cve),
				// Per-object v.Title is product-family specific boilerplate
				// ("FortiOS - HIGH - FG-IR-..."); use the advisory's document
				// title, which is descriptive and stable across the merge.
				Title:       fetched.Document.Title,
				Description: a.description,
				Severity: func() []severityTypes.Severity {
					ss := slices.Clone(a.severity)
					slices.SortFunc(ss, severityTypes.Compare)
					return slices.CompactFunc(ss, func(x, y severityTypes.Severity) bool {
						return severityTypes.Compare(x, y) == 0
					})
				}(),
				CWE: func() []cweTypes.CWE {
					cwes := slices.Compact(slices.Sorted(slices.Values(a.cwe)))
					if len(cwes) == 0 {
						return nil
					}
					return []cweTypes.CWE{{Source: "fortiguard.fortinet.com", CWE: cwes}}
				}(),
				Workarounds: func() []remediationTypes.Remediation {
					var rs []remediationTypes.Remediation
					for _, w := range slices.Compact(slices.Sorted(slices.Values(a.workarounds))) {
						rs = append(rs, remediationTypes.Remediation{Source: "fortiguard.fortinet.com", Description: w})
					}
					return rs
				}(),
				References: func() []referenceTypes.Reference {
					var rs []referenceTypes.Reference
					for _, u := range slices.Compact(slices.Sorted(slices.Values(a.references))) {
						rs = append(rs, referenceTypes.Reference{Source: "fortiguard.fortinet.com", URL: u})
					}
					return rs
				}(),
			},
			Segments: vsegs,
		})
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:    advisoryContentTypes.AdvisoryID(id),
				Title: fetched.Document.Title,
				References: []referenceTypes.Reference{{
					Source: "fortiguard.fortinet.com",
					URL:    fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", id),
				}},
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.Document.Tracking.InitialReleaseDate),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.Document.Tracking.CurrentReleaseDate),
			},
			Segments: segments,
		}},
		Vulnerabilities: vulns,
		Detections: func() []detectionTypes.Detection {
			if len(conditions) == 0 {
				return nil
			}
			return []detectionTypes.Detection{{
				Ecosystem:  ecosystemTypes.EcosystemTypeCPE,
				Conditions: conditions,
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.FortinetCSAF,
			Raws: raws,
		},
	}, nil
}

// buildProductRefs walks the product tree and maps every product_version /
// product_version_range product_id to its CPE and version expression. The
// product CPE comes from the nearest ancestor "product" branch name. Branches
// under a product name with no CPE mapping are skipped here; the whitelist is
// enforced at the known_affected use-site (toCriterion), which hard-errors so
// a new/unknown product surfaces loudly rather than being silently dropped.
func buildProductRefs(branches []csafTypes.Branch) map[string]productRef {
	refMap := make(map[string]productRef)

	var walk func(bs []csafTypes.Branch, productCPE string, mapped bool)
	walk = func(bs []csafTypes.Branch, productCPE string, mapped bool) {
		for _, b := range bs {
			pc, pm := productCPE, mapped
			switch b.Category {
			case "product_name", "product":
				pc, pm = product.ToCPE(b.Name)
			case "product_version", "product_version_range":
				if pm && b.Product != nil && b.Product.ProductID != "" {
					_, exp, _ := strings.Cut(b.Name, "/")
					refMap[string(b.Product.ProductID)] = productRef{cpe: pc, versionExp: strings.TrimSpace(exp)}
				}
			}
			walk(b.Branches, pc, pm)
		}
	}
	walk(branches, "", false)

	return refMap
}

// toCriterion resolves a known_affected product_id to a CPE criterion using the
// product tree map. It hard-errors when the product is not in the whitelist or
// its version cannot be parsed — a new Fortinet product, a new version grammar,
// or a resolver bug must fail the extract, not silently drop an affected
// product (which would be a detection false negative).
func toCriterion(productID string, refMap map[string]productRef) (criterionTypes.Criterion, error) {
	ref, ok := refMap[productID]
	if !ok {
		// Bare product reference (whole product, no version branch).
		cpe, mapped := product.ToCPE(productID)
		if !mapped {
			return criterionTypes.Criterion{}, errors.Errorf("unknown fortinet product: cannot resolve known_affected %q to a CPE (whitelist miss; add it to internal/product)", productID)
		}
		ref = productRef{cpe: cpe}
	}

	cpe := ref.cpe
	rng, bakeVersion, err := resolveVersion(ref.versionExp)
	if err != nil {
		return criterionTypes.Criterion{}, errors.Wrapf(err, "resolve version for %q", productID)
	}
	// Range-bound invariants. These two asserts are what makes the
	// RangeTypeFortinet comparator safe at detect time: they guarantee a
	// non-numeric version (FortiSASE "25.2.a") is only ever compared against a
	// numeric bound that runs out of components before the letter, never against
	// a numeric component at the same position (the comparator's "incomparable"
	// case). If Fortinet's data ever breaks an invariant, this fails loudly at
	// extract rather than silently mis-detecting later.
	if rng != nil {
		nonNumericVersioned, err := product.IsNonNumericVersioned(cpe)
		if err != nil {
			return criterionTypes.Criterion{}, errors.Wrapf(err, "check non-numeric versioning for %q", productID)
		}
		for _, b := range []string{rng.GreaterEqual, rng.GreaterThan, rng.LessEqual, rng.LessThan} {
			if b == "" {
				continue
			}
			// (1) Every bound is numeric across the whole corpus. A non-numeric
			// bound (a version like "25.2.a", which only ever appears as an
			// enumerated concrete version, never as a bound) signals an upstream
			// format change or a parsing bug.
			if !numericBound.MatchString(b) {
				return criterionTypes.Criterion{}, errors.Errorf("unexpected non-numeric range bound %q for %q (expr %q)", b, productID, ref.versionExp)
			}
			// (2) A product with non-numeric versions (e.g. FortiSASE) keeps its
			// ranges train-granular (bound dot <= 1: "25.2", not "25.2.0"). A
			// multi-component numeric bound would line a numeric component up with
			// such a version's letter — the comparator's undefined numeric-vs-
			// alphabetic case — so reject it here.
			if nonNumericVersioned && strings.Count(b, ".") >= 2 {
				return criterionTypes.Criterion{}, errors.Errorf("product %q has non-numeric versions and must use a train range (bound dot<=1), got bound %q (expr %q)", productID, b, ref.versionExp)
			}
		}
	}
	if bakeVersion != "" {
		// Validate the concrete version before baking. BakeVersion accepts many
		// CPE-legal-but-bogus shapes ("7.0.x", "v7.0.0", "7..0", "7.0.0|7.2.1"),
		// which would bake a version no scanner reports — a silent detection
		// false-negative. A numeric product must be purely numeric-dotted; a
		// non-numeric-versioned product (FortiSASE) may also carry a calendar
		// letter component ("25.2.a").
		nonNumericVersioned, err := product.IsNonNumericVersioned(cpe)
		if err != nil {
			return criterionTypes.Criterion{}, errors.Wrapf(err, "check non-numeric versioning for %q", productID)
		}
		if !numericBound.MatchString(bakeVersion) && !(nonNumericVersioned && concreteCalendarVersion.MatchString(bakeVersion)) {
			return criterionTypes.Criterion{}, errors.Errorf("unexpected concrete version %q for %q (expr %q)", bakeVersion, productID, ref.versionExp)
		}
		baked, err := product.BakeVersion(cpe, bakeVersion)
		if err != nil {
			return criterionTypes.Criterion{}, errors.Wrapf(err, "bake version for %q", productID)
		}
		cpe = baked
	}

	return criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeCPE,
		CPE: &ccTypes.Criterion{
			Vulnerable: true,
			FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
			CPE:        ccTypes.CPE(cpe),
			Range:      rng,
		},
	}, nil
}

// resolveVersion interprets a CSAF Fortinet version expression and returns
// exactly one of three outcomes, so the caller never has to guess:
//   - (range, "",   nil): narrow the CPE by this version range
//   - (nil,   ver,  nil): bake this concrete version into the CPE
//   - (nil,   "",   nil): whole product — leave the CPE version wildcarded
//
// The whole-product outcome covers an empty/"all versions" expression. A
// non-numeric "<x> all versions" (e.g. a product name leaked into the version,
// "FortiClient iOS all versions") is not silently widened to whole product —
// it hard-errors, since it never legitimately appears in known_affected data.
// numericBound matches a pure numeric-dotted version (e.g. "7.0", "7.4.3",
// "25.2.91") — the only shape Fortinet uses for a range bound. Anything with a
// non-numeric tail (e.g. "25.2.a" or "7.1-b5955") is rejected by toCriterion.
var numericBound = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// concreteCalendarVersion matches a FortiSASE-style concrete version whose
// trailing components may be a lowercase milestone letter as well as numeric
// (e.g. "25.2.a", "25.1.a.2"). It validates a bake token for a
// non-numeric-versioned product, where numericBound is too strict; both reject
// CPE-legal-but-bogus shapes like "7.0.x", "v7.0.0", "7..0" or a "7.0.0|7.2.1"
// pipe list.
var concreteCalendarVersion = regexp.MustCompile(`^[0-9]+(\.[0-9a-z]+)*$`)

func resolveVersion(exp string) (*ccRangeTypes.Range, string, error) {
	switch {
	case exp == "" || exp == "all versions":
		return nil, "", nil
	case strings.HasSuffix(exp, "all versions"):
		// "<train> all versions" → the whole X.Y train (e.g. "7.0 all versions").
		// The prefix must be a numeric train. Anything else — an empty prefix, or
		// a product name leaked into the version like "FortiClient iOS all
		// versions" — is unexpected in known_affected data, so hard-error rather
		// than silently widen to the whole product (which would mask the leak).
		train := strings.TrimSpace(strings.TrimSuffix(exp, "all versions"))
		if !numericBound.MatchString(train) {
			return nil, "", errors.Errorf("unexpected non-numeric train %q in %q", train, exp)
		}
		r, err := product.TrainRange(train)
		if err != nil {
			return nil, "", errors.Wrap(err, "train range")
		}
		return &r, "", nil
	case strings.HasSuffix(exp, " and above"):
		// Open-ended lower bound, e.g. "7.0.6 and above" → ge 7.0.6.
		return &ccRangeTypes.Range{
			Type:         ccRangeTypes.RangeTypeFortinet,
			GreaterEqual: strings.TrimSpace(strings.TrimSuffix(exp, " and above")),
		}, "", nil
	case strings.ContainsAny(exp, "<>"):
		r := ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet}
		for part := range strings.SplitSeq(exp, "|") {
			part = strings.TrimSpace(part)
			var bound *string
			var op string
			switch {
			case strings.HasPrefix(part, ">="):
				op, bound = ">=", &r.GreaterEqual
			case strings.HasPrefix(part, ">"):
				op, bound = ">", &r.GreaterThan
			case strings.HasPrefix(part, "<="):
				op, bound = "<=", &r.LessEqual
			case strings.HasPrefix(part, "<"):
				op, bound = "<", &r.LessThan
			default:
				return nil, "", errors.Errorf("unexpected bound %q in %q", part, exp)
			}
			// An empty version after the operator (e.g. ">" or ">=7.0.0|<=") would
			// be silently treated as "no constraint" by Range.Accept and over-match,
			// so reject it rather than emit an open-ended range.
			v := strings.TrimSpace(strings.TrimPrefix(part, op))
			if v == "" {
				return nil, "", errors.Errorf("empty bound %q in %q", part, exp)
			}
			*bound = v
		}
		return &r, "", nil
	case !product.IsConcrete(exp):
		// Bare train like "7.0" without the "all versions" suffix.
		r, err := product.TrainRange(exp)
		if err != nil {
			return nil, "", errors.Wrap(err, "train range")
		}
		return &r, "", nil
	default:
		// Concrete version → bake into the CPE.
		return nil, exp, nil
	}
}

func vulnSeverity(v csafTypes.Vulnerability) ([]severityTypes.Severity, error) {
	var ss []severityTypes.Severity
	seen := make(map[string]struct{})
	for _, sc := range v.Scores {
		if sc.CvssV3 == nil || sc.CvssV3.VectorString == "" {
			continue
		}
		if _, ok := seen[sc.CvssV3.VectorString]; ok {
			continue
		}
		seen[sc.CvssV3.VectorString] = struct{}{}
		// Every cvss_v3 score in the corpus is CVSS:3.1 and parseable. A non-3.1
		// vector or one that fails to parse is malformed/unexpected upstream data,
		// not a known shape we choose to skip — hard-error rather than silently
		// drop the severity.
		if !strings.HasPrefix(sc.CvssV3.VectorString, "CVSS:3.1/") {
			return nil, errors.Errorf("unexpected non-3.1 cvss vector %q", sc.CvssV3.VectorString)
		}
		c, err := v31Types.Parse(sc.CvssV3.VectorString)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss vector %q", sc.CvssV3.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.fortinet.com", CVSSv31: c})
	}
	for _, t := range v.Threats {
		if t.Category != "impact" || t.Details == "" {
			continue
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeVendor, Source: "fortiguard.fortinet.com", Vendor: new(t.Details)})
	}
	return ss, nil
}

func noteText(notes []csafTypes.Note, title string) string {
	for _, n := range notes {
		if n.Title == title {
			return strings.TrimSpace(n.Text)
		}
	}
	return ""
}

// placeholderNote reports whether a note's text is a Fortinet "no value here"
// placeholder rather than real content (the "Workarounds" note is literally
// "N/A" across the corpus), so it is dropped instead of emitted as a record.
func placeholderNote(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "none":
		return true
	default:
		return false
	}
}
