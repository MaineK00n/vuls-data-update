package cvrf

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
	var criterions []criterionTypes.Criterion
	if status := fetched.Vulnerability.ProductStatuses.Status; status.Type == "Known Affected" {
		cs, err := knownAffectedCriterions(id, status.ProductID, buildProductMap(fetched))
		if err != nil {
			return dataTypes.Data{}, errors.Wrap(err, "build known affected criterions")
		}
		criterions = cs
	}

	seg := segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeCPE}
	var (
		detections []detectionTypes.Detection
		vulnSegs   []segmentTypes.Segment
		advSegs    []segmentTypes.Segment
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
		vulnSegs = []segmentTypes.Segment{seg}
		advSegs = []segmentTypes.Segment{seg}
	}

	// CVRF carries a single advisory-level CVSS score, CWE set and reference
	// list shared across all the advisory's CVEs (e.g. FG-IR-20-104's 9.8 is
	// the advisory aggregate, not any one CVE's score). Place them on the
	// advisory; the CVEs are emitted as an enumeration carrying only their
	// CVE-specific reference links. Mirrors the jvn/feed/detail layout
	// (advisory holds severity/cwe/advisory-wide references; a vulnerability
	// holds the links that name its own CVE).
	advRefs, cveRefs := splitReferences(fetched, id)

	var vulns []vulnerabilityTypes.Vulnerability
	for _, cve := range fetched.Vulnerability.CVE {
		if cve == "" || slices.ContainsFunc(vulns, func(v vulnerabilityTypes.Vulnerability) bool {
			return v.Content.ID == vulnerabilityContentTypes.VulnerabilityID(cve)
		}) {
			continue
		}
		vulns = append(vulns, vulnerabilityTypes.Vulnerability{
			Content: vulnerabilityContentTypes.Content{
				ID:         vulnerabilityContentTypes.VulnerabilityID(cve),
				References: cveRefs[cve],
			},
			Segments: vulnSegs,
		})
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(id),
				Title:       fetched.DocumentTitle,
				Description: noteText(fetched, "Summary"),
				Severity:    advisorySeverity(fetched),
				CWE:         advisoryCWE(fetched),
				References:  advRefs,
				Published:   utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.InitialReleaseDate),
				Modified:    utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.CurrentReleaseDate),
			},
			Segments: advSegs,
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
// with the exact affected versions enumerated in CPEMatches. A wildcard main
// CPE plus a non-empty CPEMatches matches only the enumerated versions (the
// "no narrowing" path is closed once CPEMatches is populated), so this does not
// over-detect the whole product.
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
func knownAffectedCriterions(advID string, productIDs []string, prodMap map[string]productVersion) ([]criterionTypes.Criterion, error) {
	type product struct {
		cpe      string
		versions map[string]struct{} // baked exact-version CPE strings
	}
	products := make(map[string]*product)
	var order []string // product CPEs in first-seen order
	for _, pid := range productIDs {
		pv, ok := prodMap[pid]
		if !ok {
			return nil, errors.Errorf("known affected %q not found in product tree (advisory %s)", pid, advID)
		}

		cpe, ok := productpkg.ToCPE(pv.productName)
		if !ok {
			return nil, errors.Errorf("unknown fortinet product %q (whitelist miss; add it to internal/product) (advisory %s)", pv.productName, advID)
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
			return nil, errors.Wrapf(err, "bake version for %q (advisory %s)", pid, advID)
		}

		p, ok := products[cpe]
		if !ok {
			p = &product{cpe: cpe, versions: make(map[string]struct{})}
			products[cpe] = p
			order = append(order, cpe)
		}
		p.versions[baked] = struct{}{}
	}

	criterions := make([]criterionTypes.Criterion, 0, len(order))
	for _, cpe := range order {
		p := products[cpe]
		matches := make([]ccTypes.CPE, 0, len(p.versions))
		for m := range p.versions {
			matches = append(matches, ccTypes.CPE(m))
		}
		criterions = append(criterions, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				CPE:        ccTypes.CPE(cpe),
				CPEMatches: matches,
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
func advisorySeverity(fetched cvrfTypes.CVRF) []severityTypes.Severity {
	var ss []severityTypes.Severity
	if vec := fetched.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3; strings.HasPrefix(vec, "CVSS:3.1/") {
		if c, err := v31Types.Parse(vec); err != nil {
			slog.Warn("skip unparseable cvss vector", slog.String("vector", vec), slog.Any("err", err))
		} else {
			ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.fortinet.com", CVSSv31: c})
		}
	}
	return ss
}

// cwePattern matches the CWE identifiers Fortinet embeds inline in the Summary
// note, in any of the observed forms: "[CWE-200]", "(CWE-415)", "[CWE-78 ]".
var cwePattern = regexp.MustCompile(`CWE-\d+`)

// urlPattern extracts http(s) URLs from a CVRF reference string. Reference
// values are not clean URLs: some pack several URLs separated by CRLF/space,
// some wrap a URL in HTML ("<p>https://…</p>", "<a href=\"…\">…</a><br />"),
// and a few hold non-URL free text (workaround prose). Matching URLs directly
// — stopping at whitespace, quotes and angle brackets — recovers the real URL
// from every form (including href-only anchors) and yields nothing for the
// free-text entries, which are then skipped.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// cvePattern matches a CVE ID embedded in a reference URL (e.g.
// "https://nvd.nist.gov/vuln/detail/CVE-2016-0723"), so links naming a specific
// CVE can be attributed to that vulnerability rather than the whole advisory.
var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// advisoryCWE extracts CWE identifiers from the Summary note text. Unlike CSAF,
// CVRF carries no structured CWE field, so they are recovered from the prose;
// the result is advisory-level (the Summary describes the whole advisory).
func advisoryCWE(fetched cvrfTypes.CVRF) []cweTypes.CWE {
	matches := cwePattern.FindAllString(noteText(fetched, "Summary"), -1)
	if len(matches) == 0 {
		return nil
	}
	// Dedupe preserving encounter order; final ordering is applied by the
	// type's Sort() during util.Write, so no sort is needed here.
	seen := make(map[string]struct{}, len(matches))
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		ids = append(ids, m)
	}
	return []cweTypes.CWE{{Source: "fortiguard.fortinet.com", CWE: ids}}
}

// splitReferences partitions the advisory's reference URLs into an
// advisory-level list and per-CVE lists. A URL naming a CVE that is in the
// advisory's cve[] is attributed to that CVE's vulnerability (mirroring
// jvn/feed/detail, where per-CVE links live on the vulnerability); everything
// else — the canonical PSIRT URL and links that name no advisory CVE (or a CVE
// outside cve[]) — stays on the advisory. The reference values are not clean
// URLs (multiple URLs packed together, HTML wrappers, non-URL prose), so the
// real URLs are matched out via urlPattern. Each bucket is deduped.
func splitReferences(fetched cvrfTypes.CVRF, id string) (adv []referenceTypes.Reference, perCVE map[string][]referenceTypes.Reference) {
	cves := make(map[string]struct{}, len(fetched.Vulnerability.CVE))
	for _, c := range fetched.Vulnerability.CVE {
		if c != "" {
			cves[c] = struct{}{}
		}
	}

	canonical := fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", id)
	adv = []referenceTypes.Reference{{Source: "fortiguard.fortinet.com", URL: canonical}}
	advSeen := map[string]struct{}{canonical: {}}
	perCVE = make(map[string][]referenceTypes.Reference)
	cveSeen := make(map[string]map[string]struct{}) // cve -> seen URLs

	for _, r := range fetched.Vulnerability.References.Reference {
		for _, u := range urlPattern.FindAllString(r.URL, -1) {
			ref := referenceTypes.Reference{Source: "fortiguard.fortinet.com", URL: u}

			// Attribute the URL to every advisory CVE it names.
			var targets []string
			for _, m := range cvePattern.FindAllString(u, -1) {
				if _, ok := cves[strings.ToUpper(m)]; ok {
					targets = append(targets, strings.ToUpper(m))
				}
			}

			if len(targets) == 0 {
				if _, ok := advSeen[u]; ok {
					continue
				}
				advSeen[u] = struct{}{}
				adv = append(adv, ref)
				continue
			}
			for _, cve := range targets {
				if cveSeen[cve] == nil {
					cveSeen[cve] = make(map[string]struct{})
				}
				if _, ok := cveSeen[cve][u]; ok {
					continue
				}
				cveSeen[cve][u] = struct{}{}
				perCVE[cve] = append(perCVE[cve], ref)
			}
		}
	}
	return adv, perCVE
}

func noteText(fetched cvrfTypes.CVRF, title string) string {
	for _, n := range fetched.DocumentNotes.Note {
		if n.Title == title {
			return strings.TrimSpace(n.Text)
		}
	}
	return ""
}
