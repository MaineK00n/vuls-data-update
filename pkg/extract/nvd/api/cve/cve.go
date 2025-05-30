package cve

import (
	"context"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"path/filepath"
	"runtime"
	"slices"

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cpematch"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
)

type options struct {
	dir         string
	concurrency int
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type extractor struct {
	cpematchDir string
	outputDir   string
	r           *utiljson.JSONReader
}

func Extract(cveDir, cpematchDir string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "nvd", "api", "cve"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract NVD API CVE")

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
		ID:   sourceTypes.NVDAPICVE,
		Name: func() *string { t := "NVD API CVE"; return &t }(),
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
			v2, err := v2Types.Parse(c.CvssData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v2 parse. vector: %s", c.CvssData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: c.Source,
				CVSSv2: v2,
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
			ID:   sourceTypes.NVDAPICVE,
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
					CPE:  func() *cpePackageTypes.CPE { s := cpePackageTypes.CPE(match.Criteria); return &s }(),
				},
				Affected: func() *affectedTypes.Affected {
					if match.VersionStartIncluding == "" && match.VersionStartExcluding == "" &&
						match.VersionEndIncluding == "" && match.VersionEndExcluding == "" {
						return nil
					}
					a := affectedTypes.Affected{
						Type: rangeType,
						Range: []rangeTypes.Range{{
							GreaterEqual: match.VersionStartIncluding,
							GreaterThan:  match.VersionStartExcluding,
							LessEqual:    match.VersionEndIncluding,
							LessThan:     match.VersionEndExcluding,
						}},
					}
					return &a
				}(),
			},
		}

		cns := []criterionTypes.Criterion{cn}
		if rangeType == rangeTypes.RangeTypeUnknown {
			ns, err := e.cpeNamesFromCpematch(wfn, match.MatchCriteriaID)
			if err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "cpe names from cpematch. match criteria: %s", match.Criteria)
			}

			cns = slices.Grow(cns, 1+len(ns))
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
							CPE:  func() *cpePackageTypes.CPE { s := cpePackageTypes.CPE(n); return &s }(),
						},
					},
				})
			}
		}

		ca.Criterias = append(ca.Criterias, criteriaTypes.Criteria{
			Operator:   criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: cns,
		})
	}
	return ca, nil
}

func (e extractor) cpeNamesFromCpematch(wfn common.WellFormedName, matchCriteriaId string) ([]string, error) {
	h := fnv.New32()
	if _, err := fmt.Fprintf(h, "%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)); err != nil {
		return nil, errors.Wrap(err, "print vendor and product")
	}
	path := filepath.Join(e.cpematchDir, fmt.Sprintf("%x", h.Sum32()), fmt.Sprintf("%s.json", matchCriteriaId))

	var cpeMatch cpematch.MatchCriteria
	if err := e.r.Read(path, e.cpematchDir, &cpeMatch); err != nil {
		return nil, errors.Wrapf(err, "read json %s", path)
	}

	ns := make([]string, 0, len(cpeMatch.Matches))
	for _, m := range cpeMatch.Matches {
		ns = append(ns, m.CPEName)
	}
	return ns, nil
}

func decideRangeType(match cveTypes.CPEMatch) rangeTypes.RangeType {
	for _, v := range []string{match.VersionStartIncluding, match.VersionStartExcluding, match.VersionEndIncluding, match.VersionEndExcluding} {
		switch v {
		case "":
		default:
			_, err := version.NewSemver(v)
			if err != nil {
				return rangeTypes.RangeTypeUnknown
			}
		}
	}
	return rangeTypes.RangeTypeSEMVER
}
