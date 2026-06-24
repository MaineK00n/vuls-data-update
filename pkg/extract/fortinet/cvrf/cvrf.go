package cvrf

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/fortinet"
	productpkg "github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
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
	cvrfTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/cvrf"
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
		dir: filepath.Join(util.CacheDir(), "extract", "fortinet", "cvrf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Fortinet CVRF")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.Wrapf(err, "walk %s", path)
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
		var fetched cvrfTypes.CVRF
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
		ID:   sourceTypes.FortinetCVRF,
		Name: new("Fortinet PSIRT Advisories (CVRF)"),
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

func extract(fetched cvrfTypes.CVRF, raws []string) (dataTypes.Data, error) {
	id := fetched.DocumentTracking.Identification.ID
	if id == "" {
		return dataTypes.Data{}, errors.New("documenttracking.identification.id is empty")
	}

	// Detection: a single untagged OR over the Known Affected products. The
	// status is shared across the advisory's CVEs, so it is not partitioned per
	// CVE. Versions are grouped per product — one criterion whose main CPE pins
	// part/vendor/product (version wildcard) and whose CPEMatches enumerate the
	// exact affected versions.
	//
	// CVRF carries a single product status whose only observed type across the
	// corpus is "Known Affected"; advisories without it (no product_statuses, or
	// a status element without a type) are content-only. Any other type is
	// unexpected — fail loudly rather than silently emit no detection.
	var criterions []criterionTypes.Criterion
	switch status := fetched.Vulnerability.ProductStatuses.Status; status.Type {
	case "Known Affected":
		cs, err := knownAffectedCriterions(status.ProductID, buildProductMap(fetched))
		if err != nil {
			return dataTypes.Data{}, errors.Wrap(err, "build known affected criterions")
		}
		criterions = cs
	case "":
		// No product status type → content-only advisory, no detection. A typed
		// status is the only thing that lists products, so a missing type must
		// come with no products; products without a type would be an affected
		// set we cannot classify and is treated as unexpected rather than
		// dropped.
		if len(status.ProductID) > 0 {
			return dataTypes.Data{}, errors.Errorf("product status lists %d product(s) but has no type", len(status.ProductID))
		}
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected product status type %q (expected %q or none)", status.Type, "Known Affected")
	}

	// The advisory and its vulnerabilities share the same segment (the cpe
	// ecosystem, untagged) — CVRF emits a single untagged detection, so there is
	// no per-CVE partitioning to distinguish them.
	var (
		detections []detectionTypes.Detection
		segs       []segmentTypes.Segment
	)
	if len(criterions) > 0 {
		detections = []detectionTypes.Detection{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
			Conditions: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: criterions,
				},
			}},
		}}
		segs = []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}}
	}

	// CVRF carries a single advisory-level CVSS score, CWE set and reference
	// list shared across all the advisory's CVEs (e.g. FG-IR-20-104's 9.8 is
	// the advisory aggregate, not any one CVE's score). Place them on the
	// advisory; the CVEs are emitted as an ID-only enumeration. Mirrors the
	// jvn/feed/detail layout (advisory holds severity/cwe/references, the
	// vulnerabilities are CVE-ID rows).
	severity, err := advisorySeverity(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "advisory severity")
	}

	var vulns []vulnerabilityTypes.Vulnerability
	for _, cve := range fetched.Vulnerability.CVE {
		if cve == "" || slices.ContainsFunc(vulns, func(v vulnerabilityTypes.Vulnerability) bool {
			return v.Content.ID == vulnerabilityContentTypes.VulnerabilityID(cve)
		}) {
			continue
		}
		vulns = append(vulns, vulnerabilityTypes.Vulnerability{
			Content:  vulnerabilityContentTypes.Content{ID: vulnerabilityContentTypes.VulnerabilityID(cve)},
			Segments: segs,
		})
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(id),
				Title:       fetched.DocumentTitle,
				Description: noteText(fetched, "Summary"),
				Severity:    severity,
				CWE:         advisoryCWE(fetched),
				References:  advisoryReferences(fetched, id),
				Published:   utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.InitialReleaseDate),
				Modified:    utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.CurrentReleaseDate),
			},
			Segments: segs,
		}},
		Vulnerabilities: vulns,
		Detections:      detections,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.FortinetCVRF,
			Raws: raws,
		},
	}, nil
}

// productVersion is a resolved CVRF product_tree leaf: the product name and the
// raw version-branch name (which sometimes carries a product-name prefix).
type productVersion struct {
	productName string
	version     string
}

// buildProductMap walks the fixed three-level CVRF product tree
// (vendor → product name → product version) and maps each leaf product_id to
// its product name and version branch name.
func buildProductMap(fetched cvrfTypes.CVRF) map[string]productVersion {
	m := make(map[string]productVersion)
	for _, pn := range fetched.ProductTree.Branch.Branch {
		for _, pv := range pn.Branch {
			if pv.FullProductName.ProductID != "" {
				m[pv.FullProductName.ProductID] = productVersion{productName: pn.Name, version: pv.Name}
			}
		}
	}
	return m
}

// knownAffectedCriterions resolves the Known Affected product_ids into one CPE
// criterion per product: the product CPE (version wildcard) as the main CPE,
// with the exact affected versions enumerated in CPEMatches. With a non-empty
// CPEMatches the "no narrowing" path is closed, so a query with a concrete
// version matches only when it is one of the enumerated versions — the wildcard
// main CPE does not over-detect the whole product. (A version-less query still
// follows the usual cpecriterion semantics: ANY matches, NA is
// version-unconfirmed.)
//
// Only concrete versions are kept. CVRF enumerates affected versions
// explicitly, so a coarse "X.Y" / "X" train (e.g. "5.0") is dropped rather than
// ranged-over: ranging "5.0" would cover all 5.0.x and over-detect. Because
// detection ORs the CVRF and CSAF datasets, the companion CSAF source supplies
// the precise ranges for the advisories present there, and the exact CVRF
// enumeration covers the rest.
//
// It hard-errors when a product_id is absent from the tree or the product is
// not whitelisted — a new Fortinet product or a resolver bug must fail the
// extract, not silently drop coverage.
func knownAffectedCriterions(productIDs []string, prodMap map[string]productVersion) ([]criterionTypes.Criterion, error) {
	type product struct {
		cpe      string
		versions []ccTypes.CPE // baked exact-version CPEs, deduped
	}
	products := make(map[string]product)
	var order []string // product CPEs in first-seen order
	for _, pid := range productIDs {
		pv, ok := prodMap[pid]
		if !ok {
			return nil, errors.Errorf("known affected %q not found in product tree", pid)
		}

		cpe, ok := productpkg.ToCPE(pv.productName)
		if !ok {
			return nil, errors.Errorf("unknown fortinet product %q (whitelist miss; add it to internal/product)", pv.productName)
		}

		// The version branch name occasionally carries the product name as a
		// prefix (e.g. "FortiSandbox Cloud 24"); strip it to leave the bare
		// version token.
		ver := strings.TrimSpace(strings.TrimPrefix(pv.version, pv.productName))
		if !isExactVersion(ver) {
			// Coarse "X.Y" / "X" trains are dropped by design (rationale in the
			// function comment above); only exact versions are enumerated.
			continue
		}

		baked, err := productpkg.BakeVersion(cpe, ver)
		if err != nil {
			return nil, errors.Wrapf(err, "bake version for %q", pid)
		}

		p, ok := products[cpe]
		if !ok {
			p.cpe = cpe
			order = append(order, cpe)
		}
		if !slices.Contains(p.versions, ccTypes.CPE(baked)) {
			p.versions = append(p.versions, ccTypes.CPE(baked))
		}
		products[cpe] = p
	}

	criterions := make([]criterionTypes.Criterion, 0, len(order))
	for _, cpe := range order {
		p := products[cpe]
		criterions = append(criterions, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				CPE:        ccTypes.CPE(p.cpe),
				CPEMatches: p.versions,
			},
		})
	}
	return criterions, nil
}

// isExactVersion reports whether a CVRF version token is a concrete release —
// three or more dot-separated components (e.g. "7.4.3", or the FortiSASE forms
// "25.2.a" / "25.1.a.2") — rather than a coarse "X.Y" / "X" train. Only exact
// versions are enumerated into a criterion's CPEMatches; trains are dropped
// (see knownAffectedCriterions).
func isExactVersion(ver string) bool {
	return strings.Count(ver, ".") >= 2
}

// advisorySeverity returns the advisory's CVSS severity. CVRF carries a single
// advisory-level scoreset (shared across the advisory's CVEs), so it lives on
// the advisory rather than on each vulnerability.
func advisorySeverity(fetched cvrfTypes.CVRF) ([]severityTypes.Severity, error) {
	vec := fetched.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3
	if vec == "" {
		// No score → no severity.
		return nil, nil
	}
	// Every non-empty vector across the corpus is a CVSS 3.1 vector that parses
	// cleanly, so an empty or 3.1 vector are the only expected shapes: a parse
	// failure or any other version is unexpected and fails the extract rather
	// than being silently dropped.
	if !strings.HasPrefix(vec, "CVSS:3.1/") {
		return nil, errors.Errorf("unexpected cvss vector %q (expected CVSS:3.1/ or empty)", vec)
	}
	c, err := v31Types.Parse(vec)
	if err != nil {
		return nil, errors.Wrapf(err, "parse cvss vector %q", vec)
	}
	return []severityTypes.Severity{{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.fortinet.com", CVSSv31: c}}, nil
}

// cwePattern matches the CWE identifiers Fortinet embeds inline in the Summary
// note, in any of the observed forms: "[CWE-200]", "(CWE-415)", "[CWE-78 ]".
var cwePattern = regexp.MustCompile(`CWE-\d+`)

// urlCandidatePattern finds candidate http(s) URL substrings in a CVRF
// reference value. The values are messy and the URL is not always at the start:
// it can sit behind a citation marker ("[1] https://…", "- https://…",
// "1. https://…"), inside prose ("…see the link: https://…"), or wrapped in
// HTML ("<p>https://…</p>", "<a href=\"…\">…</a>"). Matching the URL substring
// directly — stopping at whitespace, quotes and angle brackets — pulls it out of
// every such form (including href-only anchors); a few values are non-URL free
// text and match nothing. extractReferenceURLs then validates each candidate
// with url.Parse.
var urlCandidatePattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// extractReferenceURLs returns the well-formed http(s) URLs in a CVRF reference
// value: each urlCandidatePattern match that url.Parse accepts with an
// http/https scheme and a host. Free text and malformed candidates yield
// nothing.
func extractReferenceURLs(s string) []string {
	var urls []string
	for _, cand := range urlCandidatePattern.FindAllString(s, -1) {
		u, err := url.Parse(cand)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		urls = append(urls, cand)
	}
	return urls
}

// advisoryCWE extracts CWE identifiers from the Summary note text. Unlike CSAF,
// CVRF carries no structured CWE field, so they are recovered from the prose;
// the result is advisory-level (the Summary describes the whole advisory).
func advisoryCWE(fetched cvrfTypes.CVRF) []cweTypes.CWE {
	matches := cwePattern.FindAllString(noteText(fetched, "Summary"), -1)
	if len(matches) == 0 {
		return nil
	}
	// Dedupe the CWE IDs (a handful at most). The output order does not matter
	// here — cwe.CWE.Sort() normalises it during util.Write — so no sort is
	// needed.
	var ids []string
	for _, m := range matches {
		if !slices.Contains(ids, m) {
			ids = append(ids, m)
		}
	}
	return []cweTypes.CWE{{Source: "fortiguard.fortinet.com", CWE: ids}}
}

// advisoryReferences returns the advisory's references: the canonical PSIRT URL
// and any http(s) URLs extracted from the CVRF reference entries (which are
// advisory-wide, not per-CVE), deduped. Output ordering is normalized by Sort().
	rs := []referenceTypes.Reference{{
		Source: "fortiguard.fortinet.com",
		URL:    fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", id),
	}}
	for _, r := range fetched.Vulnerability.References.Reference {
		for _, u := range extractReferenceURLs(r.URL) {
			if !slices.ContainsFunc(rs, func(x referenceTypes.Reference) bool { return x.URL == u }) {
				rs = append(rs, referenceTypes.Reference{Source: "fortiguard.fortinet.com", URL: u})
			}
		}
	}
	return rs
}

func noteText(fetched cvrfTypes.CVRF, title string) string {
	for _, n := range fetched.DocumentNotes.Note {
		if n.Title == title {
			return strings.TrimSpace(n.Text)
		}
	}
	return ""
}
