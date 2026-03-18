// Package v2 extracts NVD Feed v2 CVE data with cpematch expansion.
//
// Key differences from the api/cve extractor:
//   - Index keys use part:vendor:product:version format (ANY for wildcard).
//   - CPE match expansion is skipped when all range endpoints and matched
//     versions are valid semver (the range criterion alone suffices).
//   - Non-semver ranges (e.g. Cisco parenthesized versions) are expanded.
//   - Cisco parenthesized versions like "12.5(1)" → "12.5.1".
//   - nx_os / nx-os normalization when looking up cpematch data.
package v2

import (
	"context"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	cpePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	cpematchTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch/v2"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

type options struct {
	dir         string
	concurrency int
}

// Option configures the extraction.
type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

// WithDir sets the output directory.
func WithDir(dir string) Option {
	return dirOption(dir)
}

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

// WithConcurrency sets the number of parallel workers.
func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type extractor struct {
	cpematchDir string
	outputDir   string
	r           *utiljson.JSONReader
}

// Extract processes NVD Feed v2 CVE data, expanding cpematch entries
// and producing extracted detection data.
func Extract(cveDir, cpematchDir string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "nvd", "feed-v2", "cve"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract NVD Feed v2 CVE")

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(options.concurrency)

	reqChan := make(chan string)
	g.Go(func() error {
		defer close(reqChan)
		if err := filepath.WalkDir(cveDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			select {
			case reqChan <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", cveDir)
		}
		return nil
	})

	for i := 0; i < options.concurrency; i++ {
		g.Go(func() error {
			for path := range reqChan {
				if err := extract(path, cveDir, cpematchDir, options.dir); err != nil {
					return errors.Wrapf(err, "extract %s", path)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return errors.Wrapf(err, "wait for walk")
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.NVDFeedCVEv2,
		Name: new("NVD Feed v2 CVE"),
		Raw: func() []repositoryTypes.Repository {
			var res []repositoryTypes.Repository
			cveGit, _ := utilgit.GetDataSourceRepository(cveDir)
			if cveGit != nil {
				res = append(res, *cveGit)
			}
			cpematchGit, _ := utilgit.GetDataSourceRepository(cpematchDir)
			if cpematchGit != nil {
				res = append(res, *cpematchGit)
			}
			return res
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

func extract(cvePath, cveDir, cpematchDir, outputDir string) error {
	e := extractor{
		cpematchDir: cpematchDir,
		outputDir:   outputDir,
		r:           utiljson.NewJSONReader(),
	}

	var fetched cveTypes.CVE
	if err := e.r.Read(cvePath, cveDir, &fetched); err != nil {
		return errors.Wrapf(err, "read json %s", cvePath)
	}

	data, err := e.buildData(fetched)
	if err != nil {
		return errors.Wrapf(err, "buildData %s", cvePath)
	}

	if err := util.Write(filepath.Join(e.outputDir, "data", filepath.Base(filepath.Dir(cvePath)), fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(e.outputDir, "data", filepath.Base(filepath.Dir(cvePath)), fmt.Sprintf("%s.json", data.ID)))
	}
	return nil
}

func (e extractor) buildData(fetched cveTypes.CVE) (dataTypes.Data, error) {
	ds, err := func() ([]detectionType.Detection, error) {
		switch len(fetched.Configurations) {
		case 0:
			return nil, nil
		default:
			rootCriteria := criteriaTypes.Criteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: make([]criteriaTypes.Criteria, 0, len(fetched.Configurations)),
			}
			for _, c := range fetched.Configurations {
				ca, err := e.configurationToCriteria(c)
				if err != nil {
					return nil, errors.Wrapf(err, "configuration to criteria. ID: %s", fetched.ID)
				}
				rootCriteria.Criterias = append(rootCriteria.Criterias, ca)
			}
			return []detectionType.Detection{{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Conditions: []conditionTypes.Condition{{
					Criteria: rootCriteria,
				}},
			}}, nil
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "build detection. ID: %s", fetched.ID)
	}

	ss := make([]severityTypes.Severity, 0, len(fetched.Metrics.CVSSMetricV2)+len(fetched.Metrics.CVSSMetricV30)+len(fetched.Metrics.CVSSMetricV31)+len(fetched.Metrics.CVSSMetricV40))
	switch cap(ss) {
	case 0:
		ss = nil
	default:
		for _, c := range fetched.Metrics.CVSSMetricV2 {
			sv2, err := v2Types.Parse(c.CvssData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v2 parse. vector: %s", c.CvssData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: c.Source,
				CVSSv2: sv2,
			})
		}
		for _, c := range fetched.Metrics.CVSSMetricV30 {
			v30, err := v30Types.Parse(c.CVSSData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v30 parse. vector: %s", c.CVSSData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  c.Source,
				CVSSv30: v30,
			})
		}
		for _, c := range fetched.Metrics.CVSSMetricV31 {
			v31, err := v31Types.Parse(c.CVSSData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v31 parse. vector: %s", c.CVSSData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  c.Source,
				CVSSv31: v31,
			})
		}
		for _, c := range fetched.Metrics.CVSSMetricV40 {
			v40, err := v40Types.Parse(c.CVSSData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v40 parse. vector: %s", c.CVSSData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv40,
				Source:  c.Source,
				CVSSv40: v40,
			})
		}
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(fetched.ID),
					Description: func() string {
						for _, d := range fetched.Descriptions {
							if d.Lang == "en" {
								return d.Value
							}
						}
						return ""
					}(),
					Severity: ss,
					CWE: func() []cweTypes.CWE {
						if len(fetched.Weaknesses) == 0 {
							return nil
						}

						m := make(map[string][]string)
						for _, w := range fetched.Weaknesses {
							for _, d := range w.Description {
								m[w.Source] = append(m[w.Source], d.Value)
							}
						}
						cs := make([]cweTypes.CWE, 0, len(m))
						for s, vs := range m {
							cs = append(cs, cweTypes.CWE{Source: s, CWE: util.Unique(vs)})
						}
						return cs
					}(),
					References: func() []referenceTypes.Reference {
						refs := make([]referenceTypes.Reference, 0, 1+len(fetched.References))
						refs = append(refs, referenceTypes.Reference{
							Source: "nvd.nist.gov",
							URL:    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", fetched.ID),
						})
						for _, r := range fetched.References {
							refs = append(refs, referenceTypes.Reference{
								Source: r.Source,
								URL:    r.URL,
							})
						}
						return refs
					}(),
					Published: utiltime.Parse([]string{"2006-01-02T15:04:05.000"}, fetched.Published),
					Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05.000"}, fetched.LastModified),
				},
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
			},
		},
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.NVDFeedCVEv2,
			Raws: e.r.Paths(),
		},
	}, nil
}

func (e extractor) configurationToCriteria(config cveTypes.Config) (criteriaTypes.Criteria, error) {
	if config.Negate {
		return criteriaTypes.Criteria{}, errors.New("negate in Config is not implemented")
	}

	ca := criteriaTypes.Criteria{}
	switch config.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	case "OR", "":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("invalid configuration operator: %s", config.Operator)
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(config.Nodes))
	for _, n := range config.Nodes {
		child, err := e.nodeToCriteria(n)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "nodeToCriteria")
		}
		ca.Criterias = append(ca.Criterias, child)
	}
	return ca, nil
}

func (e extractor) nodeToCriteria(n cveTypes.Node) (criteriaTypes.Criteria, error) {
	ca := criteriaTypes.Criteria{}
	switch n.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	case "OR":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("invalid node operator: %s", n.Operator)
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(n.CPEMatch))
	for _, match := range n.CPEMatch {
		wfn, err := naming.UnbindFS(match.Criteria)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "invalid format. CPE: %s", match.Criteria)
		}

		hasRange := match.VersionStartIncluding != "" || match.VersionStartExcluding != "" ||
			match.VersionEndIncluding != "" || match.VersionEndExcluding != ""

		rangeType := decideRangeType(match)

		cn := criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: match.Vulnerable,
				FixStatus: func() *fixstatusTypes.FixStatus {
					if match.Vulnerable {
						return &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown}
					}
					return nil
				}(),
				Package: criterionpackageTypes.Package{
					Type: criterionpackageTypes.PackageTypeCPE,
					CPE:  new(cpePackageTypes.CPE(match.Criteria)),
				},
				Affected: func() *affectedTypes.Affected {
					if !hasRange {
						return nil
					}
					return &affectedTypes.Affected{
						Type: rangeType,
						Range: []rangeTypes.Range{{
							GreaterEqual: match.VersionStartIncluding,
							GreaterThan:  match.VersionStartExcluding,
							LessEqual:    match.VersionEndIncluding,
							LessThan:     match.VersionEndExcluding,
						}},
					}
				}(),
			},
		}

		cns := []criterionTypes.Criterion{cn}

		// Decide whether to expand cpematch entries.
		// If range type is SEMVER, we trust the range criterion alone and
		// only expand if some matched CPE version falls outside the range (WARNING).
		// If range type is Unknown (non-semver), we expand.
		if hasRange && rangeType == rangeTypes.RangeTypeUnknown {
			ns, err := e.cpeNamesFromCpematch(wfn, match.MatchCriteriaID)
			if err != nil {
				log.Printf("[WARN] cpematch lookup failed for %s (criteria=%s): %v", match.MatchCriteriaID, match.Criteria, err)
			} else {
				cns = slices.Grow(cns, len(ns))
				for _, n := range ns {
					cns = append(cns, criterionTypes.Criterion{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: match.Vulnerable,
							FixStatus: func() *fixstatusTypes.FixStatus {
								if match.Vulnerable {
									return &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown}
								}
								return nil
							}(),
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeCPE,
								CPE:  new(cpePackageTypes.CPE(n)),
							},
						},
					})
				}
			}
		} else if hasRange && rangeType == rangeTypes.RangeTypeSEMVER {
			// For semver ranges, verify matched CPE versions are within the range.
			e.verifyMatchedVersionsInRange(wfn, match)
		}

		ca.Criterias = append(ca.Criterias, criteriaTypes.Criteria{
			Operator:   criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: cns,
		})
	}
	return ca, nil
}

// verifyMatchedVersionsInRange checks that all expanded CPE versions from
// cpematch actually fall within the declared range. Emits WARNINGs for
// versions outside the range.
func (e extractor) verifyMatchedVersionsInRange(wfn common.WellFormedName, match cveTypes.CPEMatch) {
	ns, err := e.cpeNamesFromCpematch(wfn, match.MatchCriteriaID)
	if err != nil {
		// cpematch data not available; skip verification
		return
	}

	for _, n := range ns {
		cpewfn, err := naming.UnbindFS(n)
		if err != nil {
			continue
		}
		// GetString returns WFN-escaped form; unescape for version parsing
		ver := unescapeWFN(cpewfn.GetString(common.AttributeVersion))
		if ver == "" || ver == "*" || ver == "-" {
			continue
		}

		sv, err := version.NewSemver(ver)
		if err != nil {
			log.Printf("[WARN] cpematch version not semver despite semver range: criteria=%s, matchedCPE=%s, version=%s",
				match.Criteria, n, ver)
			continue
		}

		if !versionInRange(sv, match) {
			log.Printf("[WARN] cpematch version outside range: criteria=%s, matchedCPE=%s, version=%s, range=[%s,%s,%s,%s]",
				match.Criteria, n, ver,
				match.VersionStartIncluding, match.VersionStartExcluding,
				match.VersionEndIncluding, match.VersionEndExcluding)
		}
	}
}

// versionInRange checks if the given semver falls within the range.
func versionInRange(v *version.Version, match cveTypes.CPEMatch) bool {
	if match.VersionStartIncluding != "" {
		bound, err := version.NewSemver(match.VersionStartIncluding)
		if err != nil {
			return false
		}
		if v.LessThan(bound) {
			return false
		}
	}
	if match.VersionStartExcluding != "" {
		bound, err := version.NewSemver(match.VersionStartExcluding)
		if err != nil {
			return false
		}
		if !v.GreaterThan(bound) {
			return false
		}
	}
	if match.VersionEndIncluding != "" {
		bound, err := version.NewSemver(match.VersionEndIncluding)
		if err != nil {
			return false
		}
		if v.GreaterThan(bound) {
			return false
		}
	}
	if match.VersionEndExcluding != "" {
		bound, err := version.NewSemver(match.VersionEndExcluding)
		if err != nil {
			return false
		}
		if !v.LessThan(bound) {
			return false
		}
	}
	return true
}

// cpeNamesFromCpematch loads the cpematch file for the given matchCriteriaId
// and returns the list of expanded CPE names.
// It tries the primary vendor:product hash and falls back to normalized
// forms (underscore ↔ hyphen) to handle NVD naming inconsistencies.
func (e extractor) cpeNamesFromCpematch(wfn common.WellFormedName, matchCriteriaId string) ([]string, error) {
	vendor := wfn.GetString(common.AttributeVendor)
	product := wfn.GetString(common.AttributeProduct)

	// Try primary hash first, then normalized variants.
	candidates := productVariants(vendor, product)
	for _, vp := range candidates {
		ns, err := e.tryLoadCpematch(vp, matchCriteriaId)
		if err == nil {
			return ns, nil
		}
	}
	return nil, errors.Errorf("cpematch not found for %s:%s (matchCriteriaId=%s)", vendor, product, matchCriteriaId)
}

func (e extractor) tryLoadCpematch(vendorProduct, matchCriteriaId string) ([]string, error) {
	h := fnv.New32()
	h.Write([]byte(vendorProduct))
	path := filepath.Join(e.cpematchDir, fmt.Sprintf("%x", h.Sum32()), fmt.Sprintf("%s.json", matchCriteriaId))

	var cpeMatch cpematchTypes.MatchCriteria
	if err := e.r.Read(path, e.cpematchDir, &cpeMatch); err != nil {
		return nil, errors.Wrapf(err, "read json %s", path)
	}

	ns := make([]string, 0, len(cpeMatch.Matches))
	for _, m := range cpeMatch.Matches {
		ns = append(ns, m.CPEName)
	}
	return ns, nil
}

// productVariants returns vendor:product strings to try for cpematch lookup.
// Handles NVD naming inconsistencies like nx_os vs nx-os.
// The input vendor/product are in WFN-escaped form (from GetString).
func productVariants(vendor, product string) []string {
	primary := vendor + ":" + product
	variants := []string{primary}

	// Unescape WFN to get raw product name for variant generation
	rawProduct := unescapeWFN(product)

	// If raw product contains underscore, try with hyphen (WFN-escaped)
	if strings.Contains(rawProduct, "_") {
		altRaw := strings.ReplaceAll(rawProduct, "_", "-")
		altEscaped := strings.ReplaceAll(altRaw, "-", `\-`)
		alt := vendor + ":" + altEscaped
		if alt != primary {
			variants = append(variants, alt)
		}
	}

	// If raw product contains hyphen, try with underscore (no WFN escaping needed)
	if strings.Contains(rawProduct, "-") {
		altRaw := strings.ReplaceAll(rawProduct, "-", "_")
		alt := vendor + ":" + altRaw
		if alt != primary {
			variants = append(variants, alt)
		}
	}
	return variants
}

// decideRangeType checks if all range endpoints are valid semver.
func decideRangeType(match cveTypes.CPEMatch) rangeTypes.RangeType {
	for _, v := range []string{match.VersionStartIncluding, match.VersionStartExcluding, match.VersionEndIncluding, match.VersionEndExcluding} {
		if v == "" {
			continue
		}
		if _, err := version.NewSemver(v); err != nil {
			return rangeTypes.RangeTypeUnknown
		}
	}
	return rangeTypes.RangeTypeSEMVER
}

// IndexKey returns the index key for a CPE formatted string
// in the format "part:vendor:product:version".
// For version=* (ANY), returns "ANY".
func IndexKey(cpe string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "unbind CPE %q", cpe)
	}

	part := wfn.GetString(common.AttributePart)
	vendor := unescapeWFN(wfn.GetString(common.AttributeVendor))
	product := unescapeWFN(wfn.GetString(common.AttributeProduct))
	ver := unescapeWFN(wfn.GetString(common.AttributeVersion))

	if ver == "" || ver == "*" {
		ver = "ANY"
	}

	return fmt.Sprintf("%s:%s:%s:%s", part, vendor, product, ver), nil
}

// unescapeWFN removes WFN backslash escaping from attribute values.
// e.g. "7\\.1\\.2" → "7.1.2"
func unescapeWFN(s string) string {
	return strings.ReplaceAll(s, "\\", "")
}
