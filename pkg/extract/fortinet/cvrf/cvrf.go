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

	// Detection: a single untagged OR over the Known Affected product versions.
	// The status is shared across the advisory's CVEs, so it is not partitioned
	// per CVE.
	var criterions []criterionTypes.Criterion
	if status := fetched.Vulnerability.ProductStatuses.Status; status.Type == "Known Affected" {
		prodMap := buildProductMap(fetched)
		criterions = make([]criterionTypes.Criterion, 0, len(status.ProductID))
		seen := make(map[string]struct{}, len(status.ProductID))
		for _, pid := range status.ProductID {
			cn, err := toCriterion(pid, prodMap)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "resolve known affected %q (advisory %s)", pid, id)
			}
			key := string(cn.CPE.CPE)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			criterions = append(criterions, cn)
		}
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

	severity := vulnSeverity(fetched)
	references := vulnReferences(fetched)
	cwes := vulnCWE(fetched)

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
				Title:      fetched.Vulnerability.Title,
				Severity:   severity,
				CWE:        cwes,
				References: references,
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
				References: []referenceTypes.Reference{{
					Source: "fortiguard.fortinet.com",
					URL:    fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", id),
				}},
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.InitialReleaseDate),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.DocumentTracking.CurrentReleaseDate),
				Optional:  advisoryOptional(fetched),
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

// toCriterion resolves a Known Affected product_id to a CPE criterion. It
// hard-errors when the product_id is absent from the tree, the product is not
// in the whitelist, or its version cannot be parsed — a new Fortinet product,
// a new version grammar, or a resolver bug must fail the extract, not silently
// drop an affected product (which would be a detection false negative).
func toCriterion(productID string, prodMap map[string]productVersion) (criterionTypes.Criterion, error) {
	pv, ok := prodMap[productID]
	if !ok {
		return criterionTypes.Criterion{}, errors.Errorf("known affected %q not found in product tree", productID)
	}

	cpe, ok := product.ToCPE(pv.productName)
	if !ok {
		return criterionTypes.Criterion{}, errors.Errorf("unknown fortinet product %q (whitelist miss; add it to internal/product)", pv.productName)
	}

	// The version branch name occasionally carries the product name as a prefix
	// (e.g. "FortiSandbox Cloud 24"); strip it to leave the bare version token.
	ver := strings.TrimSpace(strings.TrimPrefix(pv.version, pv.productName))

	c := ccTypes.Criterion{
		Vulnerable: true,
		FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
		CPE:        ccTypes.CPE(cpe),
	}
	if ver != "" {
		// CVRF enumerates affected versions, so each is baked into the CPE
		// exactly — no version range. A CVRF "X.Y" train (e.g. "5.0") is too
		// coarse to range over ("5.0" would cover all 5.0.x and over-detect);
		// since detection ORs the CVRF and CSAF datasets, the precise CSAF
		// range covers the advisories present there, and the exact CVRF
		// enumeration covers the rest.
		baked, err := product.BakeVersion(cpe, ver)
		if err != nil {
			return criterionTypes.Criterion{}, errors.Wrapf(err, "bake version for %q", productID)
		}
		c.CPE = ccTypes.CPE(baked)
	}

	return criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &c}, nil
}

func vulnSeverity(fetched cvrfTypes.CVRF) []severityTypes.Severity {
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

// vulnCWE extracts CWE identifiers from the Summary note text. Unlike CSAF,
// CVRF carries no structured CWE field, so they are recovered from the prose.
func vulnCWE(fetched cvrfTypes.CVRF) []cweTypes.CWE {
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

func vulnReferences(fetched cvrfTypes.CVRF) []referenceTypes.Reference {
	var rs []referenceTypes.Reference
	for _, r := range fetched.Vulnerability.References.Reference {
		// A single reference url sometimes packs several URLs separated by
		// CRLF/whitespace; emit one Reference per URL.
		for u := range strings.FieldsSeq(r.URL) {
			rs = append(rs, referenceTypes.Reference{Source: "fortiguard.fortinet.com", URL: u})
		}
	}
	return rs
}

// advisoryOptional collects the free-text notes (Description / Solutions /
// Affected Products, when not the placeholder "None"). These have no
// structured home but carry residual value, especially for the older
// advisories that have no product statuses.
func advisoryOptional(fetched cvrfTypes.CVRF) map[string]any {
	m := make(map[string]any)
	for _, title := range []string{"Description", "Solutions", "Affected Products"} {
		if t := noteText(fetched, title); t != "" && !strings.EqualFold(t, "None") {
			m[strings.ToLower(strings.ReplaceAll(title, " ", "_"))] = t
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func noteText(fetched cvrfTypes.CVRF, title string) string {
	for _, n := range fetched.DocumentNotes.Note {
		if n.Title == title {
			return strings.TrimSpace(n.Text)
		}
	}
	return ""
}
