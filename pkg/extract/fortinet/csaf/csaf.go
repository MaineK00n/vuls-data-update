package csaf

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
	"maps"
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

// productRef is a product_tree leaf's ancestor product name plus the version
// expression carried in its branch name (the part after "<product>/"). The name
// is resolved to a CPE at the use site (toCriterion), which also enforces the
// whitelist.
type productRef struct {
	productName string
	versionExp  string
}

// keyAcc accumulates one vulnerability key — a CVE, or the advisory ID when a
// CSAF vulnerability object carries no CVE (a few older Fortinet advisories are
// published without one). description/cwe/references/workarounds are CVE-level
// (shared across the key); severity, criterions and mitigations live per
// severity group (see sevGroup). String slices are deduped on emit.
type keyAcc struct {
	description string
	cwe         []string
	references  []string
	workarounds []string
	groups      map[sevKey]*sevGroup
}

// sevKey groups the per-family CSAF vulnerability objects of one key by their
// severity profile (CVSS vector(s) + vendor impact). CSAF scopes scores to
// .products and impact threats to .product_ids; Fortinet replicates one CVE
// across one object per product family. Today every family shares the same
// severity, so a key collapses to a single group and the per-CVE output is
// unchanged — but distinct severities (which CSAF permits) split into separate
// segments/conditions rather than being over-attributed to every product.
type sevKey struct {
	cvss   string
	impact string
}

type sevGroup struct {
	severities  []severityTypes.Severity
	criterions  []criterionTypes.Criterion
	mitigations []string
	pids        []string // known_affected product_ids, for a stable split tag suffix
}

func extract(fetched csafTypes.CSAF, raws []string) (dataTypes.Data, error) {
	id := fetched.Document.Tracking.ID
	if id == "" {
		return dataTypes.Data{}, errors.New("document.tracking.id is empty")
	}

	refMap := buildProductRefs(fetched.ProductTree.Branches)

	// Merge the per-family CSAF vulnerability objects by key (CVE, or advisory
	// ID when a object has no CVE), distributing each object's score / impact /
	// vendor_fix remediation to its own family and grouping families by severity
	// profile.
	accs := make(map[string]*keyAcc)
	for _, v := range fetched.Vulnerabilities {
		key := v.CVE
		if key == "" {
			key = id
		}
		a := accs[key]
		if a == nil {
			a = &keyAcc{groups: make(map[sevKey]*sevGroup)}
			accs[key] = a
		}

		if a.description == "" {
			a.description = noteText(v.Notes, "Summary")
		}
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

		sevs, sk, err := vulnSeverity(v)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "severity for advisory %s, %s", id, key)
		}
		g := a.groups[sk]
		if g == nil {
			g = &sevGroup{severities: sevs}
			a.groups[sk] = g
		}
		for _, pid := range v.ProductStatus.KnownAffected {
			cn, err := toCriterion(string(pid), refMap)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "resolve known_affected %q (advisory %s, %s)", string(pid), id, key)
			}
			g.criterions = append(g.criterions, cn)
			g.pids = append(g.pids, string(pid))
		}
		for _, rem := range v.Remediations {
			switch rem.Category {
			case "vendor_fix":
				// Per-train fix guidance ("FortiOS 7.4: Upgrade to 7.4.8 ...").
				if rem.Details != "" {
					g.mitigations = append(g.mitigations, rem.Details)
				}
			default:
				return dataTypes.Data{}, errors.Errorf("unexpected remediation category %q (advisory %s, %s)", rem.Category, id, key)
			}
		}
	}

	var (
		vulns      []vulnerabilityTypes.Vulnerability
		conditions []conditionTypes.Condition
		segments   []segmentTypes.Segment
	)
	for key, a := range accs {
		// Sort the severity groups so a multi-group key gets stable tag suffixes.
		gkeys := slices.SortedFunc(maps.Keys(a.groups), func(x, y sevKey) int {
			return cmp.Or(cmp.Compare(x.cvss, y.cvss), cmp.Compare(x.impact, y.impact))
		})
		for _, sk := range gkeys {
			g := a.groups[sk]

			// One severity group → the tag is the bare key (CVE / advisory ID),
			// keeping the common single-group output stable. Multiple groups
			// within one key → suffix each tag with a hash of the group's largest
			// product_id (the groups partition the products, so the maxima differ).
			// Keying the suffix on the product set, not on a positional index or
			// the severity value, keeps the tag stable across data updates (it
			// only moves if that group's products change), minimizing extracted
			// diff — mirroring redhat/csaf's calculateTag.
			tag := segmentTypes.DetectionTag(key)
			if len(gkeys) > 1 && len(g.pids) > 0 {
				h := fnv.New32a()
				// hash.Hash.Write is documented never to return an error.
				_, _ = h.Write([]byte(slices.Max(g.pids)))
				tag = segmentTypes.DetectionTag(fmt.Sprintf("%s_%08x", key, h.Sum32()))
			}
			seg := segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: tag}

			// Only carry the tagged segment when it has a matching detection
			// condition. A group with no known_affected (e.g. known_not_affected
			// only) otherwise leaves a dangling segment tag with no condition or
			// advisory segment, producing an internally inconsistent dataset.
			var vsegs []segmentTypes.Segment
			if len(g.criterions) > 0 {
				segments = append(segments, seg)
				vsegs = []segmentTypes.Segment{seg}
				conditions = append(conditions, conditionTypes.Condition{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: g.criterions,
					},
					Tag: tag,
				})
			}

			// A no-CVE key (the advisory ID) emits only the advisory segment and
			// detection condition above — no Vulnerability record. The consumer
			// synthesizes a VulnInfo from the advisory ID via its advisory
			// fallback, which fires only when no Vulnerability shares the tag.
			if key == id {
				continue
			}

			vulns = append(vulns, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(key),
					// Per-object v.Title is product-family specific boilerplate
					// ("FortiOS - HIGH - FG-IR-..."); use the advisory's document
					// title, which is descriptive and stable across the merge.
					Title:       fetched.Document.Title,
					Description: a.description,
					Severity: func() []severityTypes.Severity {
						ss := slices.Clone(g.severities)
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
					Mitigations: func() []remediationTypes.Remediation {
						var rs []remediationTypes.Remediation
						for _, m := range slices.Compact(slices.Sorted(slices.Values(g.mitigations))) {
							rs = append(rs, remediationTypes.Remediation{Source: "fortiguard.fortinet.com", Description: m})
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
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:    advisoryContentTypes.AdvisoryID(id),
				Title: fetched.Document.Title,
				// A no-CVE advisory carries its summary here (keyed by the advisory
				// ID), since the consumer's advisory fallback reads the advisory
				// Description; CVE advisories keep descriptions on their per-CVE
				// vulnerability records instead.
				Description: func() string {
					if a, ok := accs[id]; ok {
						return a.description
					}
					return ""
				}(),
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
// product_version_range product_id to its ancestor product name and version
// expression. The name → CPE whitelist is resolved and enforced at the
// known_affected use-site (toCriterion), which hard-errors so a new/unknown
// product surfaces loudly rather than being silently dropped.
func buildProductRefs(branches []csafTypes.Branch) map[string]productRef {
	refMap := make(map[string]productRef)

	var walk func(bs []csafTypes.Branch, productName string)
	walk = func(bs []csafTypes.Branch, productName string) {
		for _, b := range bs {
			pn := productName
			switch b.Category {
			case "product_name", "product":
				pn = b.Name
			case "product_version", "product_version_range":
				if pn != "" && b.Product != nil && b.Product.ProductID != "" {
					// Leaf names take two forms: "<product>/<version-exp>"
					// (e.g. "FortiOS/>=7.0.0|<=7.0.5") and, in some advisories,
					// "<product> <version>" with no slash (e.g. "FortiOS 5.0.0").
					// Take the version after "/" when present, else strip the
					// product-name prefix — otherwise the version would be empty
					// and the product would wildcard to all versions (over-detect).
					exp, found := "", false
					if _, after, ok := strings.Cut(b.Name, "/"); ok {
						exp, found = after, true
					}
					if !found {
						exp = strings.TrimPrefix(b.Name, pn)
					}
					refMap[string(b.Product.ProductID)] = productRef{productName: pn, versionExp: strings.TrimSpace(exp)}
				}
			default:
			}
			walk(b.Branches, pn)
		}
	}
	walk(branches, "")

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
		return criterionTypes.Criterion{}, errors.Errorf("cannot resolve known_affected %q to a product_version in the tree", productID)
	}

	cpe, rt, ok := product.Resolve(ref.productName)
	if !ok {
		return criterionTypes.Criterion{}, errors.Errorf("unknown fortinet product %q (known_affected %q; add it to internal/product)", ref.productName, productID)
	}

	rng, bakeVersion, err := resolveVersion(ref.versionExp)
	if err != nil {
		return criterionTypes.Criterion{}, errors.Wrapf(err, "resolve version for %q", productID)
	}
	// rt (the product's per-product range type, resolved above) selects the
	// detect-time comparator; it is only consulted on the range/bake paths.
	if rng != nil || bakeVersion != "" {
		// Range-bound invariants. These two asserts keep a non-numeric-versioned product's
		// comparator safe at detect time: they guarantee a non-numeric version
		// (FortiSASE "25.2.a") is only ever compared against a numeric bound that
		// runs out of components before the letter, never against a numeric
		// component at the same position (the comparator's "incomparable" case).
		// If Fortinet's data ever breaks an invariant, this fails loudly at
		// extract rather than silently mis-detecting later.
		if rng != nil {
			rng.Type = rt
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
				// (2) A non-numeric-versioned product (e.g. FortiSASE) keeps its ranges
				// train-granular (bound dot <= 1: "25.2", not "25.2.0"). A
				// multi-component numeric bound would line a numeric component up with
				// such a version's letter — the comparator's undefined numeric-vs-
				// alphabetic case — so reject it here.
				if rt == ccRangeTypes.RangeTypeFortinetFortiSASE && strings.Count(b, ".") >= 2 {
					return criterionTypes.Criterion{}, errors.Errorf("product %q is non-numeric-versioned and must use a train range (bound dot<=1), got bound %q (expr %q)", productID, b, ref.versionExp)
				}
			}
		}
		if bakeVersion != "" {
			// Validate the concrete version before baking. BakeVersion accepts many
			// CPE-legal-but-bogus shapes ("7.0.x", "v7.0.0", "7..0", "7.0.0|7.2.1"),
			// which would bake a version no scanner reports — a silent detection
			// false-negative. A numeric product must be purely numeric-dotted; a
			// non-numeric-versioned product (FortiSASE) may also carry a
			// milestone-letter component ("25.2.a").
			validVersion := numericBound.MatchString(bakeVersion) || (rt == ccRangeTypes.RangeTypeFortinetFortiSASE && concreteNonNumericVersion.MatchString(bakeVersion))
			if !validVersion {
				return criterionTypes.Criterion{}, errors.Errorf("unexpected concrete version %q for %q (expr %q)", bakeVersion, productID, ref.versionExp)
			}
			baked, err := product.BakeVersion(cpe, bakeVersion)
			if err != nil {
				return criterionTypes.Criterion{}, errors.Wrapf(err, "bake version for %q", productID)
			}
			cpe = baked
		}
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

// numericBound matches a pure numeric-dotted version (e.g. "7.0", "7.4.3",
// "25.2.91") — the only shape Fortinet uses for a range bound. Anything with a
// non-numeric tail (e.g. "25.2.a" or "7.1-b5955") is rejected by toCriterion.
var numericBound = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// concreteNonNumericVersion matches a FortiSASE-style concrete version: a numeric
// head plus trailing components that are each either numeric or a single
// lowercase milestone letter (e.g. "25.2.a", "25.1.a.2"). It validates a bake
// token for a non-numeric-versioned product, where numericBound is too strict.
// Each component is constrained so ambiguous tokens the Fortinet comparator
// can't order meaningfully ("25.1.a10", "25.2.alpha", "7.0.x", "v7.0.0",
// "7..0", a "7.0.0|7.2.1" pipe list) fail loudly instead of being baked.
var concreteNonNumericVersion = regexp.MustCompile(`^[0-9]+(\.([0-9]+|[a-z]))*$`)

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
		ge := strings.TrimSpace(strings.TrimSuffix(exp, " and above"))
		if ge == "" {
			// No version before "and above" → an empty bound would be treated as
			// "no constraint" and widen to the whole product, so reject it.
			return nil, "", errors.Errorf("empty lower bound in %q", exp)
		}
		// Type is set by the caller (toCriterion), which knows the product.
		return &ccRangeTypes.Range{GreaterEqual: ge}, "", nil
	case strings.ContainsAny(exp, "<>"):
		r := ccRangeTypes.Range{}
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

// vulnSeverity returns the severities for one CSAF vulnerability object (its
// per-family CVSS v3.1 score and vendor impact) together with the sevKey that
// groups families of the same key by identical severity profile. Fortinet emits
// exactly one cvss vector and one impact per object; anything else (zero or
// multiple distinct) is a hard error (see below), not silently handled.
func vulnSeverity(v csafTypes.Vulnerability) ([]severityTypes.Severity, sevKey, error) {
	var ss []severityTypes.Severity
	var vectors, impacts []string
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
			return nil, sevKey{}, errors.Errorf("unexpected non-3.1 cvss vector %q", sc.CvssV3.VectorString)
		}
		c, err := v31Types.Parse(sc.CvssV3.VectorString)
		if err != nil {
			return nil, sevKey{}, errors.Wrapf(err, "parse cvss vector %q", sc.CvssV3.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.fortinet.com", CVSSv31: c})
		vectors = append(vectors, sc.CvssV3.VectorString)
	}
	seenImpact := make(map[string]struct{})
	for _, t := range v.Threats {
		if t.Category != "impact" || t.Details == "" {
			continue
		}
		if _, ok := seenImpact[t.Details]; ok {
			continue
		}
		seenImpact[t.Details] = struct{}{}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeVendor, Source: "fortiguard.fortinet.com", Vendor: new(t.Details)})
		impacts = append(impacts, t.Details)
	}
	// Fortinet emits exactly one cvss vector and one impact per vulnerability
	// object (verified across the corpus). Zero or more than one distinct of
	// either would drop or mis-map a severity, so fail loudly — this path only
	// runs in CI, so a silent fallback would go unnoticed; it is the signal to
	// revisit the per-family grouping.
	if len(vectors) != 1 {
		return nil, sevKey{}, errors.Errorf("vulnerability %q has %d distinct cvss vectors, want exactly 1 (%s)", v.CVE, len(vectors), strings.Join(vectors, ", "))
	}
	if len(impacts) != 1 {
		return nil, sevKey{}, errors.Errorf("vulnerability %q has %d distinct impacts, want exactly 1 (%s)", v.CVE, len(impacts), strings.Join(impacts, ", "))
	}
	return ss, sevKey{cvss: vectors[0], impact: impacts[0]}, nil
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
