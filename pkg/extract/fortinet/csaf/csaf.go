package csaf

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	nonnumericVersion "github.com/vulsio/go-fortinet-version/nonnumeric"
	numericVersion "github.com/vulsio/go-fortinet-version/numeric"

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
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/extract/util/filepath"
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

		if err := fixProductTree(&fetched); err != nil {
			return errors.Wrapf(err, "fix product tree %s", path)
		}

		data, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		y, err := fortinet.YearDir(string(data.ID))
		if err != nil {
			return errors.Wrapf(err, "year dir %s", path)
		}

		p, err := utilfilepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", data.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, data, true); err != nil {
			return errors.Wrapf(err, "write %s", p)
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
// is resolved to a CPE at the use site (toCriterions), which also enforces the
// whitelist.
type productRef struct {
	productName string
	versionExp  string
}

// keyAcc accumulates one vulnerability key — a CVE, or the advisory ID when a
// CSAF vulnerability object carries no CVE (a few older Fortinet advisories are
// published without one). description/cwe/references/workarounds are CVE-level
// (shared across the key). The rest is scoped to products: collection records,
// as read from the CSAF, whether each listed product is affected and which
// profile it gets; emit groups the products by profile, into one segment /
// condition / Vulnerability record each, and converts both to the output
// types. String slices are deduped on emit.
type keyAcc struct {
	description string
	cwe         []string
	references  []string
	workarounds []string
	products    map[string]productStatus // listed product_id → what the CSAF says of it
}

// productStatus is what the CSAF says of one product of a key: whether it is
// listed known_affected or known_not_affected, and the profile it gets. A
// known_not_affected product is emitted as a not-affected criterion beside the
// affected ones of its profile, the way the Ubuntu and Debian extractors carry
// theirs, so a key whose products are all not affected still has a segment.
type productStatus struct {
	affected bool
	profile  profile
}

// profile is the content CSAF scopes to products, which may therefore differ
// between the products of one key — the severity (CVSS vector + vendor
// impact) and the mitigations, held as read so that it compares and keys a
// map. CSAF scopes scores to .products, and threats and remediations to
// .product_ids, so each product gets the score, impact and mitigations that
// list it (see vulnProfile); Fortinet replicates one CVE across one object per
// product family. Today every family shares the same profile, so a key has a
// single profile and the per-CVE output is unchanged — but distinct profiles
// (which CSAF permits) split into separate segments/conditions rather than
// being over-attributed to every product.
type profile struct {
	cvss   string // CVSS v3.1 vector, empty when no score lists the product
	impact string // empty when no impact threat covers the product
	// mitigations is the texts of the "mitigation" remediations listing the
	// product: distinct, sorted and NUL-joined, so that the profile stays
	// comparable. Empty for a product no mitigation lists.
	mitigations string
}

// hash returns a digest of the profile, telling the profiles of one key apart
// in their tags.
func (p profile) hash() uint32 {
	h := fnv.New32a()
	// hash.Hash.Write is documented never to return an error.
	_, _ = fmt.Fprintf(h, "%s\x00%s", p.cvss, p.impact)
	// Written only when present, so that a profile without mitigations keeps
	// the digest, and with it the tag, it had before profiles carried them.
	if p.mitigations != "" {
		_, _ = fmt.Fprintf(h, "\x00%s", p.mitigations)
	}
	return h.Sum32()
}

// mitigationRecords converts the profile's mitigations to the Mitigations of
// its Vulnerability record, one per text, in the sorted order they are held
// in.
func (p profile) mitigationRecords() []remediationTypes.Remediation {
	if p.mitigations == "" {
		return nil
	}
	var rs []remediationTypes.Remediation
	for m := range strings.SplitSeq(p.mitigations, "\x00") {
		rs = append(rs, remediationTypes.Remediation{Source: "fortiguard.fortinet.com", Description: m})
	}
	return rs
}

// severities converts the profile to the severities of its Vulnerability
// record: one for each of the CVSS vector and the impact the profile has, so
// none for a profile with neither. The CVSS vector is parsed here, once; a
// vector that does not parse is malformed upstream data and hard-errors rather
// than being dropped.
func (p profile) severities() ([]severityTypes.Severity, error) {
	var ss []severityTypes.Severity
	if p.cvss != "" {
		c, err := v31Types.Parse(p.cvss)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss vector %q", p.cvss)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.fortinet.com", CVSSv31: c})
	}
	if p.impact != "" {
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeVendor, Source: "fortiguard.fortinet.com", Vendor: new(p.impact)})
	}
	return ss, nil
}

func extract(fetched csafTypes.CSAF, raws []string) (dataTypes.Data, error) {
	id := fetched.Document.Tracking.ID
	if id == "" {
		return dataTypes.Data{}, errors.New("document.tracking.id is empty")
	}

	refMap, err := buildProductRefs(id, fetched.ProductTree.Branches)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "build product refs")
	}

	// Merge the per-family CSAF vulnerability objects by key (CVE, or advisory
	// ID when a object has no CVE), distributing each score / impact to the
	// products it names, known_affected or known_not_affected, and grouping
	// products by profile. Product references are read as CSAF has them,
	// product_ids; the Fortinet spelling is rewritten to that by
	// fixProductTree.
	accs := make(map[string]*keyAcc)
	for _, v := range fetched.Vulnerabilities {
		key := v.CVE
		if key == "" {
			key = id
		}
		a := accs[key]
		if a == nil {
			a = &keyAcc{products: make(map[string]productStatus)}
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

		// Every object lists its products as known_affected or
		// known_not_affected; one listing neither would carry a profile no
		// product gets, so that hard-errors. A product_id listed twice (a few
		// trees define a leaf twice) is one product; listed with two statuses or
		// getting two profiles, it would contradict itself, so that hard-errors
		// rather than picking one.
		if len(v.ProductStatus.KnownAffected) == 0 && len(v.ProductStatus.KnownNotAffected) == 0 {
			return dataTypes.Data{}, errors.Errorf("vulnerability object lists neither known_affected nor known_not_affected products (advisory %s, %s)", id, key)
		}
		// Fortinet uses no other product_status category (546 CSAF advisories
		// as of 2026-09). A product listed under one would be dropped unnoticed
		// — fixed releases moved out of known_not_affected, say, taking their
		// not-affected criterions with them — so any of them hard-errors.
		for name, pids := range map[string][]csafTypes.ProductID{
			"first_affected":      v.ProductStatus.FirstAffected,
			"first_fixed":         v.ProductStatus.FirstFixed,
			"fixed":               v.ProductStatus.Fixed,
			"last_affected":       v.ProductStatus.LastAffected,
			"recommended":         v.ProductStatus.Recommended,
			"under_investigation": v.ProductStatus.UnderInvestigation,
		} {
			if len(pids) > 0 {
				return dataTypes.Data{}, errors.Errorf("unexpected product_status.%s %q (advisory %s, %s)", name, pids, id, key)
			}
		}
		// Each score, and each impact scoped to products, is read for the
		// listed products it names (see vulnProfile). One naming none of them —
		// filed in the wrong object, say — would be read for no product and its
		// severity lost unnoticed, now that a product may lack a score or an
		// impact, so that hard-errors.
		listed := slices.Concat(v.ProductStatus.KnownAffected, v.ProductStatus.KnownNotAffected)
		reachesListed := func(pids []csafTypes.ProductID) bool {
			return slices.ContainsFunc(pids, func(pid csafTypes.ProductID) bool { return slices.Contains(listed, pid) })
		}
		for _, sc := range v.Scores {
			if !reachesListed(sc.Products) {
				return dataTypes.Data{}, errors.Errorf("score of %q names none of the listed products (products: %q, listed: %q) (advisory %s)", key, sc.Products, listed, id)
			}
		}
		for _, t := range v.Threats {
			if t.Category == "impact" && len(t.ProductIDs) > 0 && !reachesListed(t.ProductIDs) {
				return dataTypes.Data{}, errors.Errorf("impact of %q names none of the listed products (product_ids: %q, listed: %q) (advisory %s)", key, t.ProductIDs, listed, id)
			}
		}
		// A mitigation is read the same way, so one naming none of the listed
		// products would be dropped unnoticed as well.
		for _, rem := range v.Remediations {
			if rem.Category == "mitigation" && !reachesListed(rem.ProductIDs) {
				return dataTypes.Data{}, errors.Errorf("mitigation of %q names none of the listed products (product_ids: %q, listed: %q) (advisory %s)", key, rem.ProductIDs, listed, id)
			}
		}
		for _, l := range []struct {
			pids     []csafTypes.ProductID
			affected bool
		}{
			{pids: v.ProductStatus.KnownAffected, affected: true},
			{pids: v.ProductStatus.KnownNotAffected, affected: false},
		} {
			for _, pid := range l.pids {
				p, err := vulnProfile(v, string(pid))
				if err != nil {
					return dataTypes.Data{}, errors.Wrapf(err, "profile of %q for advisory %s, %s", string(pid), id, key)
				}
				ps := productStatus{affected: l.affected, profile: p}
				if prev, ok := a.products[string(pid)]; ok && prev != ps {
					return dataTypes.Data{}, errors.Errorf("product %q is listed twice, contradicting itself (%+v, %+v) (advisory %s, %s)", string(pid), prev, ps, id, key)
				}
				a.products[string(pid)] = ps
			}
		}
		for _, rem := range v.Remediations {
			switch rem.Category {
			case "vendor_fix":
				// The fix — the upgrade target, e.g. "FortiOS 7.4: Upgrade to
				// 7.4.8" — is already encoded structurally in the detection version
				// range, and the CVRF extractor likewise carries no fix text. Don't
				// duplicate it as a mitigation: it is the fix, not a mitigation or
				// workaround, and the schema has no fix bucket.
			case "mitigation":
				// A measure short of the fix, e.g. the FortiGuard IPS virtual
				// patch of FG-IR-26-157. Its text is carried per product: it
				// is part of the profile of each product it lists (vulnProfile)
				// and emitted as the Mitigations of that profile's
				// Vulnerability record, so a mitigation for one family does
				// not reach the others. This case only admits the category.
				// "workaround", "no_fix_planned" and "none_available" have not
				// appeared in the corpus and stay in default, so the first one
				// is routed deliberately.
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
		// Group the products' criterions by profile. Iteration order is
		// irrelevant: each tag is derived from the profile itself (below), and
		// util.Write re-sorts every output slice by a content-based total order,
		// so the append order never reaches the output.
		type group struct {
			criterions []criterionTypes.Criterion
			criterias  []criteriaTypes.Criteria
		}
		profiles := make(map[profile]*group)
		for pid, ps := range a.products {
			cns, err := toCriterions(pid, refMap)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "resolve product %q (advisory %s, %s)", pid, id, key)
			}
			if !ps.affected {
				for _, cn := range cns {
					cn.CPE.Vulnerable = false
					cn.CPE.FixStatus = &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassNotAffected}
				}
			}
			g := profiles[ps.profile]
			if g == nil {
				g = &group{}
				profiles[ps.profile] = g
			}
			// A product recorded under several CPEs is one OR of its criterions,
			// so each product stays one unit even where two products share a CPE.
			switch len(cns) {
			case 1:
				g.criterions = append(g.criterions, cns[0])
			default:
				g.criterias = append(g.criterias, criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cns,
				})
			}
		}

		// One profile → the tag is the bare key (CVE / advisory ID), keeping the
		// common single-profile output stable. Multiple profiles within one key →
		// suffix each tag with a hash of the profile, so a tag moves only when its
		// profile's content does, which changes the Vulnerability record anyway.
		// A product-based suffix would move with every version range Fortinet
		// edits into a product_id. Distinct profiles may still hash alike, and two
		// sharing a tag would tie each one's condition to the other's record, so a
		// collision hard-errors rather than picking one.
		tags := make(map[profile]segmentTypes.DetectionTag, len(profiles))
		for p := range profiles {
			tag := segmentTypes.DetectionTag(key)
			if len(profiles) > 1 {
				tag = segmentTypes.DetectionTag(fmt.Sprintf("%s_%08x", key, p.hash()))
			}
			for q, t := range tags {
				if t == tag {
					return dataTypes.Data{}, errors.Errorf("profiles %+v and %+v hash to one tag %q (advisory %s, %s)", q, p, tag, id, key)
				}
			}
			tags[p] = tag
		}

		for p, g := range profiles {
			tag := tags[p]
			sevs, err := p.severities()
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "severity for advisory %s, %s", id, key)
			}

			seg := segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: tag}

			// Every profile comes from a listed product, so each has criterions
			// and its segment a matching condition.
			segments = append(segments, seg)
			conditions = append(conditions, conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterias:  g.criterias,
					Criterions: g.criterions,
				},
				Tag: tag,
			})

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
					Severity:    sevs,
					CWE: func() []cweTypes.CWE {
						cwes := slices.Compact(slices.Sorted(slices.Values(a.cwe)))
						if len(cwes) == 0 {
							return nil
						}
						return []cweTypes.CWE{{Source: "fortiguard.fortinet.com", CWE: cwes}}
					}(),
					Mitigations: p.mitigationRecords(),
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
				Segments: []segmentTypes.Segment{seg},
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

// buildProductRefs maps every product_version / product_version_range product_id
// to its ancestor product name and version expression. Two product-tree dialects
// exist: all current advisories use the standard one (product nodes are category
// "product", version leaves are named "<product>/<expr>"); exactly one historical
// advisory (FG-IR-21-173) uses a legacy one (category "product_name", leaves
// "<product> <version>" with a space and no slash). Switch on the advisory ID so
// the exception is explicit and bounded, and have each dialect hard-error when
// its assumption is violated — so Fortinet standardizing FG-IR-21-173, or a new
// legacy-format advisory, surfaces loudly instead of being silently mis-parsed.
// The name → CPE whitelist is resolved and enforced later, for each listed
// product, at the use-site (toCriterions).
func buildProductRefs(id string, branches []csafTypes.Branch) (map[string]productRef, error) {
	switch id {
	case "FG-IR-21-173":
		return buildProductRefsLegacy(branches)
	default:
		return buildProductRefsStandard(branches)
	}
}

// buildProductRefsStandard maps a standard-dialect product tree: product nodes
// are category "product" and version leaves are named "<product>/<expr>". It
// hard-errors on a legacy-dialect node (category "product_name") or a version
// leaf without the "/" separator.
func buildProductRefsStandard(branches []csafTypes.Branch) (map[string]productRef, error) {
	refMap := make(map[string]productRef)

	var walk func(bs []csafTypes.Branch, productName string) error
	walk = func(bs []csafTypes.Branch, productName string) error {
		for _, b := range bs {
			pn := productName
			switch b.Category {
			case "product_name":
				return errors.Errorf("unexpected legacy product_name node %q in a standard-dialect advisory", b.Name)
			case "product":
				pn = b.Name
			case "product_version", "product_version_range":
				if pn != "" && b.Product != nil && b.Product.ProductID != "" {
					_, after, ok := strings.Cut(b.Name, "/")
					if !ok {
						return errors.Errorf("standard-dialect version leaf %q has no %q separator", b.Name, "/")
					}
					refMap[string(b.Product.ProductID)] = productRef{productName: pn, versionExp: strings.TrimSpace(after)}
				}
			default:
			}
			if err := walk(b.Branches, pn); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(branches, ""); err != nil {
		return nil, err
	}

	return refMap, nil
}

// buildProductRefsLegacy maps the legacy-dialect product tree of the one advisory
// that uses it (FG-IR-21-173): product nodes are category "product_name" and
// version leaves are named "<product> <version>" (a space, no slash). It
// hard-errors on a standard-dialect node (category "product"), a slash-containing
// leaf, or a leaf not prefixed by its product name.
func buildProductRefsLegacy(branches []csafTypes.Branch) (map[string]productRef, error) {
	refMap := make(map[string]productRef)

	var walk func(bs []csafTypes.Branch, productName string) error
	walk = func(bs []csafTypes.Branch, productName string) error {
		for _, b := range bs {
			pn := productName
			switch b.Category {
			case "product":
				return errors.Errorf("unexpected standard product node %q in the legacy-dialect advisory", b.Name)
			case "product_name":
				pn = b.Name
			case "product_version", "product_version_range":
				if pn != "" && b.Product != nil && b.Product.ProductID != "" {
					if strings.Contains(b.Name, "/") {
						return errors.Errorf("legacy-dialect version leaf %q unexpectedly contains %q", b.Name, "/")
					}
					exp, ok := strings.CutPrefix(b.Name, pn)
					if !ok {
						return errors.Errorf("legacy-dialect version leaf %q is not prefixed by product name %q", b.Name, pn)
					}
					refMap[string(b.Product.ProductID)] = productRef{productName: pn, versionExp: strings.TrimSpace(exp)}
				}
			default:
			}
			if err := walk(b.Branches, pn); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(branches, ""); err != nil {
		return nil, err
	}

	return refMap, nil
}

// toCriterions resolves a listed product_id, known_affected or
// known_not_affected, to CPE criterions using the product tree map, one per
// CPE the product may be recorded under (see product.Resolve), each with the
// same version constraint. It hard-errors when the product is not in the
// whitelist or its version cannot be parsed — a new Fortinet product, a new
// version grammar, or a resolver bug must fail the extract, not silently drop
// a listed product (an affected one dropped would be a detection false
// negative, a not-affected one a lost exclusion).
func toCriterions(productID string, refMap map[string]productRef) ([]criterionTypes.Criterion, error) {
	ref, ok := refMap[productID]
	if !ok {
		return nil, errors.Errorf("cannot resolve %q to a product_version in the tree", productID)
	}

	cpes, rt, ok := product.Resolve(ref.productName)
	if !ok {
		return nil, errors.Errorf("unknown fortinet product %q (%q; add it to internal/product)", ref.productName, productID)
	}

	r, bakeVersion, err := resolveVersion(ref.productName, ref.versionExp)
	if err != nil {
		return nil, errors.Wrapf(err, "resolve version for %q", productID)
	}
	// rt (the product's per-product range type, resolved above) selects the
	// detect-time comparator; it is only consulted on the range/bake paths below.
	//
	// Range-bound invariants. The first two asserts keep a non-numeric-versioned
	// product's comparator safe at detect time: they guarantee a non-numeric
	// version (FortiSASE "25.2.a") is only ever compared against a numeric bound
	// that runs out of components before the letter, never against a numeric
	// component at the same position (the comparator's "incomparable" case). The
	// third keeps the range satisfiable. If Fortinet's data ever breaks an
	// invariant, this fails loudly at extract rather than silently
	// mis-detecting later.
	if r != nil {
		r.Type = rt
		for _, b := range []string{r.GreaterEqual, r.GreaterThan, r.LessEqual, r.LessThan} {
			if b == "" {
				continue
			}
			// (1) Every bound is numeric across the whole corpus. A non-numeric
			// bound (a version like "25.2.a", which only ever appears as an
			// enumerated concrete version, never as a bound) signals an upstream
			// format change or a parsing bug.
			if _, err := numericVersion.NewVersion(b); err != nil {
				return nil, errors.Wrapf(err, "unexpected non-numeric range bound %q for %q (expr %q)", b, productID, ref.versionExp)
			}
			// (2) A non-numeric-versioned product (e.g. FortiSASE) keeps its ranges
			// train-granular (bound dot <= 1: "25.2", not "25.2.0"). A
			// multi-component numeric bound would line a numeric component up with
			// such a version's letter — the comparator's undefined numeric-vs-
			// alphabetic case — so reject it here.
			if rt == ccRangeTypes.RangeTypeFortinetFortiSASE && strings.Count(b, ".") >= 2 {
				return nil, errors.Errorf("product %q is non-numeric-versioned and must use a train range (bound dot<=1), got bound %q (expr %q)", productID, b, ref.versionExp)
			}
		}
		// (3) Reject a range no version can satisfy: extraction would succeed
		// and the detector never match, a silent false negative. Two shapes: a
		// lower bound above the upper one (">=7.2.7|<=7.2.0"), and equal bounds
		// with an exclusive side (">7.2.0|<7.2.0", ">7.2.0|<=7.2.0"), since
		// Range.Accept rejects the bound value itself for gt/lt. Equal inclusive
		// bounds (">=7.2.0|<=7.2.0") are a one-version range and stay allowed.
		// The CVRF supplement rejects the same shapes.
		//
		// resolveVersion sets at most one bound per side, so reading one field
		// of each side is the whole range.
		if lo, hi := cmp.Or(r.GreaterEqual, r.GreaterThan), cmp.Or(r.LessEqual, r.LessThan); lo != "" && hi != "" {
			vlo, err := numericVersion.NewVersion(lo)
			if err != nil {
				return nil, errors.Wrapf(err, "parse lower bound %q for %q (expr %q)", lo, productID, ref.versionExp)
			}
			vhi, err := numericVersion.NewVersion(hi)
			if err != nil {
				return nil, errors.Wrapf(err, "parse upper bound %q for %q (expr %q)", hi, productID, ref.versionExp)
			}
			c, err := vlo.Compare(vhi)
			if err != nil {
				return nil, errors.Wrapf(err, "compare bounds %q, %q for %q (expr %q)", lo, hi, productID, ref.versionExp)
			}
			switch {
			case c > 0:
				return nil, errors.Errorf("inverted range for %q: lower bound %q > upper bound %q (expr %q)", productID, lo, hi, ref.versionExp)
			case c == 0 && (r.GreaterThan != "" || r.LessThan != ""):
				return nil, errors.Errorf("empty range for %q: bounds %q and %q are equal but not both inclusive (expr %q)", productID, lo, hi, ref.versionExp)
			}
		}
	}
	if bakeVersion != "" {
		// Validate the concrete version before baking. BakeVersion accepts many
		// CPE-legal-but-bogus shapes ("7.0.x", "v7.0.0", "7..0", "7.0.0|7.2.1"),
		// which would bake a version no scanner reports — a silent detection
		// false-negative. Defer "is this a real version" to the same parser the
		// detector uses: a numeric product must parse under the numeric scheme,
		// a non-numeric-versioned product (FortiSASE) under the milestone scheme
		// (which also accepts a single letter component, "25.2.a").
		switch rt {
		case ccRangeTypes.RangeTypeFortinetFortiSASE:
			if _, err := nonnumericVersion.NewVersion(bakeVersion); err != nil {
				return nil, errors.Wrapf(err, "unexpected concrete version %q for %q (expr %q)", bakeVersion, productID, ref.versionExp)
			}
		default:
			if _, err := numericVersion.NewVersion(bakeVersion); err != nil {
				return nil, errors.Wrapf(err, "unexpected concrete version %q for %q (expr %q)", bakeVersion, productID, ref.versionExp)
			}
		}
		for i, cpe := range cpes {
			baked, err := product.BakeVersion(cpe, bakeVersion)
			if err != nil {
				return nil, errors.Wrapf(err, "bake version for %q", productID)
			}
			cpes[i] = baked
		}
	}

	cns := make([]criterionTypes.Criterion, 0, len(cpes))
	for _, cpe := range cpes {
		cns = append(cns, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				CPE:        ccTypes.CPE(cpe),
				// Each criterion gets its own copy, so no two share a Range.
				Range: func() *ccRangeTypes.Range {
					if r == nil {
						return nil
					}
					c := *r
					return &c
				}(),
			},
		})
	}
	return cns, nil
}

// resolveVersion interprets a CSAF Fortinet version expression for the named
// product and returns exactly one of three outcomes, so the caller never has
// to guess:
//   - (range, "",   nil): narrow the CPE by this version range
//   - (nil,   ver,  nil): bake this concrete version into the CPE
//   - (nil,   "",   nil): whole product — leave the CPE version wildcarded
//
// The product name decides the exact-vs-train split for a bare version token
// (product.IsExactVersion): "7.166" is a concrete IPS Engine build to bake,
// but "7.4" is a FortiOS train to range-over. The whole-product outcome
// covers an empty/"all versions" expression. A non-numeric "<x> all versions"
// (e.g. a product name leaked into the version, "FortiClient iOS all
// versions") is not silently widened to whole product — it hard-errors, since
// it never legitimately appears in a listed product's version.
func resolveVersion(productName, exp string) (*ccRangeTypes.Range, string, error) {
	switch {
	case exp == "" || exp == "all versions":
		return nil, "", nil
	case strings.HasSuffix(exp, "all versions"):
		// "<train> all versions" → the whole X.Y train (e.g. "7.0 all versions").
		// The prefix must be a numeric train. Anything else — an empty prefix, or
		// a product name leaked into the version like "FortiClient iOS all
		// versions" — is unexpected in a listed product's version, so
		// hard-error rather than silently widen to the whole product (which
		// would mask the leak).
		train := strings.TrimSpace(strings.TrimSuffix(exp, "all versions"))
		if _, err := numericVersion.NewVersion(train); err != nil {
			return nil, "", errors.Wrapf(err, "unexpected non-numeric train %q in %q", train, exp)
		}
		r, err := product.TrainRange(productName, train)
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
		// Type is set by the caller (toCriterions), which knows the product.
		return &ccRangeTypes.Range{GreaterEqual: ge}, "", nil
	case strings.ContainsAny(exp, "<>"):
		r := ccRangeTypes.Range{}
		// At most one bound per side. A repeated side (">7.2.7|>=7.2.0|<=7.2.5",
		// ">=7.0.0|>=7.2.0") would either set both fields of that side, and the
		// order check in toCriterions reads only one of them, or overwrite the
		// first value with the second; either way the emitted range is not the
		// one written, so reject it rather than pick a bound.
		seen := make(map[string]bool, 2)
		for part := range strings.SplitSeq(exp, "|") {
			part = strings.TrimSpace(part)
			var bound *string
			var op, side string
			switch {
			case strings.HasPrefix(part, ">="):
				op, bound, side = ">=", &r.GreaterEqual, "lower"
			case strings.HasPrefix(part, ">"):
				op, bound, side = ">", &r.GreaterThan, "lower"
			case strings.HasPrefix(part, "<="):
				op, bound, side = "<=", &r.LessEqual, "upper"
			case strings.HasPrefix(part, "<"):
				op, bound, side = "<", &r.LessThan, "upper"
			default:
				return nil, "", errors.Errorf("unexpected bound %q in %q", part, exp)
			}
			if seen[side] {
				return nil, "", errors.Errorf("more than one %s bound in %q", side, exp)
			}
			seen[side] = true
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
	case !product.IsExactVersion(productName, exp):
		// Bare train like "7.0" without the "all versions" suffix.
		r, err := product.TrainRange(productName, exp)
		if err != nil {
			return nil, "", errors.Wrap(err, "train range")
		}
		return &r, "", nil
	default:
		// Concrete version → bake into the CPE.
		return nil, exp, nil
	}
}

// vulnProfile returns the profile of one CSAF vulnerability object for the
// product_id pid: the CVSS v3.1 vector of the score whose .products lists pid,
// the vendor impact whose .product_ids lists pid or which has none (and so
// covers the whole object), and the texts of the "mitigation" remediations
// whose .product_ids lists pid. CSAF requires neither a score nor a threat, so
// either, or both, may be missing, leaving that part of the profile empty;
// more than one distinct of either is a hard error (see below). Mitigations
// are optional and any number may list a product.
func vulnProfile(v csafTypes.Vulnerability, pid string) (profile, error) {
	// Fortinet emits at most one cvss vector and one impact per product. Hold a
	// single value and fail loudly on a second distinct one (a duplicate of the
	// same value is tolerated): picking one would mis-map a severity, and this
	// path only runs in CI, so a silent fallback would go unnoticed — a hard
	// error is the signal to revisit the grouping.
	var vector string
	for _, sc := range v.Scores {
		if !slices.Contains(sc.Products, csafTypes.ProductID(pid)) {
			continue
		}
		// A score may be missing, but one that lists the product carries its
		// vector: without it the severity would be dropped unnoticed.
		if sc.CvssV3 == nil || sc.CvssV3.VectorString == "" {
			return profile{}, errors.Errorf("score of %q listing %q has no cvss_v3 vector", v.CVE, pid)
		}
		if vector != "" && vector != sc.CvssV3.VectorString {
			return profile{}, errors.Errorf("vulnerability %q has multiple distinct cvss vectors (%q, %q)", v.CVE, vector, sc.CvssV3.VectorString)
		}
		vector = sc.CvssV3.VectorString
	}
	// Every cvss_v3 score in the corpus is CVSS:3.1 and parseable. A non-3.1
	// vector is unexpected upstream data, not a known shape we choose to skip —
	// hard-error rather than silently drop it (one that fails to parse errors
	// on emit, in profile.severities).
	if vector != "" && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return profile{}, errors.Errorf("unexpected non-3.1 cvss vector %q", vector)
	}

	var impact string
	for _, t := range v.Threats {
		if t.Category != "impact" || (len(t.ProductIDs) > 0 && !slices.Contains(t.ProductIDs, csafTypes.ProductID(pid))) {
			continue
		}
		// Likewise an impact that covers the product carries its details
		// (CSAF requires them).
		if t.Details == "" {
			return profile{}, errors.Errorf("impact of %q covering %q has no details", v.CVE, pid)
		}
		if impact != "" && impact != t.Details {
			return profile{}, errors.Errorf("vulnerability %q has multiple distinct impacts (%q, %q)", v.CVE, impact, t.Details)
		}
		impact = t.Details
	}
	// A placeholder text ("N/A") is no mitigation and is dropped, as it is for
	// the Workarounds note. A NUL in a text would split it in two when the
	// joined texts are read back on emit, so that hard-errors.
	var mitigations []string
	for _, rem := range v.Remediations {
		if rem.Category != "mitigation" || !slices.Contains(rem.ProductIDs, csafTypes.ProductID(pid)) {
			continue
		}
		m := strings.TrimSpace(rem.Details)
		if placeholderNote(m) {
			continue
		}
		if strings.Contains(m, "\x00") {
			return profile{}, errors.Errorf("vulnerability %q has a mitigation containing a NUL character", v.CVE)
		}
		mitigations = append(mitigations, m)
	}
	slices.Sort(mitigations)

	return profile{cvss: vector, impact: impact, mitigations: strings.Join(slices.Compact(mitigations), "\x00")}, nil
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
