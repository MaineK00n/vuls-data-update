package csaf

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
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
	title            string
	description      string
	severity         []severityTypes.Severity
	cwe              []string
	workarounds      []string
	references       []string
	knownNotAffected []string
	criterions       []criterionTypes.Criterion
}

func extract(fetched csafTypes.CSAF, raws []string) (dataTypes.Data, error) {
	id := fetched.Document.Tracking.ID
	if id == "" {
		return dataTypes.Data{}, errors.New("document.tracking.id is empty")
	}

	refMap, unconverted := buildProductRefs(fetched.ProductTree.Branches)

	// Fortinet splits one logical CVE across several CSAF vulnerability objects
	// (one per product family), each repeating the scores/notes. Merge them by
	// CVE so each CVE yields a single vulnerability record and condition.
	var order []string
	accs := make(map[string]*cveAcc)
	for _, v := range fetched.Vulnerabilities {
		if v.CVE == "" {
			slog.Warn("skip vulnerability without CVE", slog.String("advisory", id))
			continue
		}

		a, ok := accs[v.CVE]
		if !ok {
			a = &cveAcc{}
			accs[v.CVE] = a
			order = append(order, v.CVE)
		}

		if a.title == "" {
			a.title = v.Title
		}
		if a.description == "" {
			a.description = noteText(v.Notes, "Summary")
		}
		a.severity = append(a.severity, vulnSeverity(v)...)
		if v.CWE != nil && v.CWE.ID != "" {
			a.cwe = append(a.cwe, v.CWE.ID)
		}
		if w := noteText(v.Notes, "Workarounds"); w != "" {
			a.workarounds = append(a.workarounds, w)
		}
		for _, r := range v.References {
			if r.URL != "" {
				a.references = append(a.references, r.URL)
			}
		}
		for _, pid := range v.ProductStatus.KnownNotAffected {
			a.knownNotAffected = append(a.knownNotAffected, string(pid))
		}
		for _, pid := range v.ProductStatus.KnownAffected {
			cn, ok := toCriterion(string(pid), refMap)
			if !ok {
				if !slices.Contains(unconverted, string(pid)) {
					unconverted = append(unconverted, string(pid))
				}
				slog.Warn("failed to resolve known_affected product", slog.String("advisory", id), slog.String("product_id", string(pid)))
				continue
			}
			a.criterions = append(a.criterions, cn)
		}
	}

	var (
		vulns      []vulnerabilityTypes.Vulnerability
		conditions []conditionTypes.Condition
		segments   []segmentTypes.Segment
	)
	for _, cve := range order {
		a := accs[cve]
		seg := segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: segmentTypes.DetectionTag(cve)}

		if len(a.criterions) > 0 {
			segments = append(segments, seg)
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
				ID:          vulnerabilityContentTypes.VulnerabilityID(cve),
				Title:       a.title,
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
					return []cweTypes.CWE{{Source: "fortiguard.com", CWE: cwes}}
				}(),
				Workarounds: func() []remediationTypes.Remediation {
					var rs []remediationTypes.Remediation
					for _, w := range slices.Compact(slices.Sorted(slices.Values(a.workarounds))) {
						rs = append(rs, remediationTypes.Remediation{Source: "fortiguard.com", Description: w})
					}
					return rs
				}(),
				References: func() []referenceTypes.Reference {
					var rs []referenceTypes.Reference
					for _, u := range slices.Compact(slices.Sorted(slices.Values(a.references))) {
						rs = append(rs, referenceTypes.Reference{Source: "fortiguard.com", URL: u})
					}
					return rs
				}(),
				Optional: func() map[string]any {
					nas := slices.Compact(slices.Sorted(slices.Values(a.knownNotAffected)))
					if len(nas) == 0 {
						return nil
					}
					return map[string]any{"known_not_affected": nas}
				}(),
			},
			Segments: []segmentTypes.Segment{seg},
		})
	}

	slices.Sort(unconverted)
	unconverted = slices.Compact(unconverted)

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:    advisoryContentTypes.AdvisoryID(id),
				Title: fetched.Document.Title,
				References: []referenceTypes.Reference{{
					Source: "fortiguard.com",
					URL:    fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", id),
				}},
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.Document.Tracking.InitialReleaseDate),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05", time.RFC3339}, fetched.Document.Tracking.CurrentReleaseDate),
				Optional: func() map[string]any {
					if len(unconverted) == 0 {
						return nil
					}
					return map[string]any{"unconverted_product_names": unconverted}
				}(),
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
// product CPE comes from the nearest ancestor "product" branch name. Product
// names with no CPE mapping are collected as unconverted.
func buildProductRefs(branches []csafTypes.Branch) (map[string]productRef, []string) {
	refMap := make(map[string]productRef)
	var unconverted []string

	var walk func(bs []csafTypes.Branch, productName, productCPE string, mapped bool)
	walk = func(bs []csafTypes.Branch, productName, productCPE string, mapped bool) {
		for _, b := range bs {
			pn, pc, pm := productName, productCPE, mapped
			switch b.Category {
			case "product_name", "product":
				pn = b.Name
				pc, pm = product.ToCPE(b.Name)
				if !pm && !slices.Contains(unconverted, b.Name) {
					unconverted = append(unconverted, b.Name)
				}
			case "product_version", "product_version_range":
				if b.Product != nil && b.Product.ProductID != "" {
					_, exp, _ := strings.Cut(b.Name, "/")
					if pm {
						refMap[string(b.Product.ProductID)] = productRef{cpe: pc, versionExp: strings.TrimSpace(exp)}
					}
				}
			}
			walk(b.Branches, pn, pc, pm)
		}
	}
	walk(branches, "", "", false)

	return refMap, unconverted
}

// toCriterion resolves a known_affected product_id to a CPE criterion using the
// product tree map. Returns false when the product cannot be resolved.
func toCriterion(productID string, refMap map[string]productRef) (criterionTypes.Criterion, bool) {
	ref, ok := refMap[productID]
	if !ok {
		// Bare product reference (whole product, no version branch).
		if cpe, mapped := product.ToCPE(productID); mapped {
			ref = productRef{cpe: cpe}
		} else {
			return criterionTypes.Criterion{}, false
		}
	}

	cpe := ref.cpe
	rng, err := versionRange(ref.versionExp)
	if err != nil {
		slog.Warn("failed to build version range", slog.String("product_id", productID), slog.Any("err", err))
		return criterionTypes.Criterion{}, false
	}

	if rng == nil && ref.versionExp != "" && ref.versionExp != "all versions" {
		// Concrete single version → bake into the CPE.
		baked, err := product.BakeVersion(cpe, ref.versionExp)
		if err != nil {
			slog.Warn("failed to bake version", slog.String("product_id", productID), slog.Any("err", err))
			return criterionTypes.Criterion{}, false
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
	}, true
}

// versionRange parses a CSAF Fortinet version expression into a range, or nil
// when the expression denotes a concrete version ("7.4.3"), the whole product
// ("all versions" / ""), so the caller bakes / leaves the CPE as-is.
func versionRange(exp string) (*ccRangeTypes.Range, error) {
	switch {
	case exp == "" || exp == "all versions":
		return nil, nil
	case strings.HasSuffix(exp, "all versions"):
		// "<train> all versions" → the whole X.Y train. When the prefix is
		// not a numeric train (e.g. the product name leaked in as
		// "FortiClient iOS all versions"), treat it as the whole product.
		train := strings.TrimSpace(strings.TrimSuffix(exp, "all versions"))
		if train == "" || (train[0] < '0' || train[0] > '9') {
			return nil, nil
		}
		r, err := product.TrainRange(train)
		if err != nil {
			return nil, errors.Wrap(err, "train range")
		}
		return &r, nil
	case strings.HasSuffix(exp, " and above"):
		// Open-ended lower bound, e.g. "7.0.6 and above" → ge 7.0.6.
		return &ccRangeTypes.Range{
			Type:         ccRangeTypes.RangeTypeFortinet,
			GreaterEqual: strings.TrimSpace(strings.TrimSuffix(exp, " and above")),
		}, nil
	case strings.ContainsAny(exp, "<>"):
		r := ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet}
		for part := range strings.SplitSeq(exp, "|") {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, ">="):
				r.GreaterEqual = strings.TrimSpace(strings.TrimPrefix(part, ">="))
			case strings.HasPrefix(part, ">"):
				r.GreaterThan = strings.TrimSpace(strings.TrimPrefix(part, ">"))
			case strings.HasPrefix(part, "<="):
				r.LessEqual = strings.TrimSpace(strings.TrimPrefix(part, "<="))
			case strings.HasPrefix(part, "<"):
				r.LessThan = strings.TrimSpace(strings.TrimPrefix(part, "<"))
			default:
				return nil, errors.Errorf("unexpected bound %q in %q", part, exp)
			}
		}
		return &r, nil
	case !product.IsConcrete(exp):
		// Bare train like "7.0" without the "all versions" suffix.
		r, err := product.TrainRange(exp)
		if err != nil {
			return nil, errors.Wrap(err, "train range")
		}
		return &r, nil
	default:
		// Concrete version → caller bakes into the CPE.
		return nil, nil
	}
}

func vulnSeverity(v csafTypes.Vulnerability) []severityTypes.Severity {
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
		if !strings.HasPrefix(sc.CvssV3.VectorString, "CVSS:3.1/") {
			slog.Warn("skip non-3.1 cvss vector", slog.String("cve", v.CVE), slog.String("vector", sc.CvssV3.VectorString))
			continue
		}
		c, err := v31Types.Parse(sc.CvssV3.VectorString)
		if err != nil {
			slog.Warn("skip unparseable cvss vector", slog.String("cve", v.CVE), slog.Any("err", err))
			continue
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: "fortiguard.com", CVSSv31: c})
	}
	for _, t := range v.Threats {
		if t.Category != "impact" || t.Details == "" {
			continue
		}
		d := t.Details
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeVendor, Source: "fortiguard.com", Vendor: &d})
	}
	return ss
}

func noteText(notes []csafTypes.Note, title string) string {
	for _, n := range notes {
		if n.Title == title {
			return strings.TrimSpace(n.Text)
		}
	}
	return ""
}
