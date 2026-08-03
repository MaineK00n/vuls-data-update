package json

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	httpdjson "github.com/MaineK00n/vuls-data-update/pkg/fetch/apache/httpd/json"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	cpecriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	cperangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
)

// Every record describes the one product, so the criterion CPE is fixed and
// only the version part varies.
const (
	productCPE  = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
	versionCPE  = "cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*"
	sourceLabel = "httpd.apache.org"
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
		dir: filepath.Join(util.CacheDir(), "extract", "apache", "httpd", "json"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Apache HTTP Server CVE (JSON)")
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

		extracted, err := extractFile(path, args)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.ApacheHTTPDJSON,
		Name: new("Apache HTTP Server CVE (JSON)"),
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

// extractFile reads one fetched record. The ASF serves two schema generations
// side by side, so which type to decode into is decided by the version member
// the record carries, the same way the fetcher routes them.
func extractFile(path, args string) (dataTypes.Data, error) {
	r := utiljson.NewJSONReader()

	var probe struct {
		DataVersion4 string `json:"data_version"`
		DataVersion5 string `json:"dataVersion"`
	}
	if err := r.Read(path, args, &probe); err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "read json %s", path)
	}

	switch {
	case probe.DataVersion5 != "":
		var fetched httpdjson.CVE5
		if err := r.Read(path, args, &fetched); err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "read json %s", path)
		}
		return extract5(fetched, r.Paths()), nil
	case probe.DataVersion4 != "":
		var fetched httpdjson.CVE4
		if err := r.Read(path, args, &fetched); err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "read json %s", path)
		}
		return extract4(fetched, r.Paths()), nil
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected schema. expected one of: %q", []string{"data_version", "dataVersion"})
	}
}

func extract4(fetched httpdjson.CVE4, raws []string) dataTypes.Data {
	// version_data enumerates concrete versions with "=" (verified) or "?="
	// (listed but unverified, per the vulnerability page's own wording); the
	// 2021-2022 records instead bound a range with "<=" for the upper end and
	// ">=" / "!<" ("not less than") for the lower one. Exact versions become
	// CPEMatches, bounds become a Range — the two never co-occur in the current
	// corpus, but the criterion carries both fields so a record using them
	// together still extracts.
	var (
		matches []cpecriterionTypes.CPE
		rng     cperangeTypes.Range
		bounded bool
	)
	for _, vendor := range fetched.Affects.Vendor.VendorData {
		for _, product := range vendor.Product.ProductData {
			for _, v := range product.Version.VersionData {
				switch v.VersionAffected {
				case "=", "?=":
					matches = append(matches, cpecriterionTypes.CPE(fmt.Sprintf(versionCPE, v.VersionValue)))
				case "<=":
					rng.LessEqual = v.VersionValue
					bounded = true
				case "<":
					rng.LessThan = v.VersionValue
					bounded = true
				case ">=", "!<":
					rng.GreaterEqual = v.VersionValue
					bounded = true
				case ">":
					rng.GreaterThan = v.VersionValue
					bounded = true
				default:
					// A comparator the CVE JSON 4.0 vocabulary allows but the
					// ASF has never used. Skipping it would silently shrink the
					// affected set, so record it and move on rather than drop
					// the whole record.
					slog.Warn("skip unsupported version_affected", "cve", fetched.CVEDataMeta.ID, "version_affected", v.VersionAffected, "version_value", v.VersionValue)
				}
			}
		}
	}
	if bounded {
		rng.Type = cperangeTypes.RangeTypeSEMVER
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.CVEDataMeta.ID),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:    vulnerabilityContentTypes.VulnerabilityID(fetched.CVEDataMeta.ID),
				Title: fetched.CVEDataMeta.Title,
				Description: func() string {
					for _, d := range fetched.Description.DescriptionData {
						if d.Lang == "eng" || d.Lang == "en" {
							return d.Value
						}
					}
					return ""
				}(),
				Severity: func() []severityTypes.Severity {
					var ss []severityTypes.Severity
					for _, i := range fetched.Impact {
						if i.Other == "" || i.Other == "n/a" {
							continue
						}
						ss = append(ss, severityTypes.Severity{
							Type:   severityTypes.SeverityTypeVendor,
							Source: sourceLabel,
							Vendor: &i.Other,
						})
					}
					return ss
				}(),
				// problemtype_data carries the flaw's short name here, not a
				// CWE identifier, so there is nothing to map onto cwe.
				References: func() []referenceTypes.Reference {
					var rs []referenceTypes.Reference
					for _, ref := range fetched.References.ReferenceData {
						if ref.URL == nil || *ref.URL == "" {
							continue
						}
						rs = append(rs, referenceTypes.Reference{
							Source: sourceLabel,
							URL:    *ref.URL,
						})
					}
					return rs
				}(),
				Published: func() *time.Time {
					if fetched.CVEDataMeta.DatePublic == nil || *fetched.CVEDataMeta.DatePublic == "" {
						return nil
					}
					return utiltime.Parse([]string{"2006-01-02"}, *fetched.CVEDataMeta.DatePublic)
				}(),
			},
			Segments: segments(matches, bounded),
		}},
		Detections: detections(matches, rng, bounded),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.ApacheHTTPDJSON,
			Raws: raws,
		},
	}
}

func extract5(fetched httpdjson.CVE5, raws []string) dataTypes.Data {
	cna := fetched.Containers.CNA

	// A versions[] entry with an upper bound describes a range; one carrying
	// only "version" pins that single release. "0" is the schema's way of
	// saying "from the first release", so it sets no lower bound.
	var (
		matches []cpecriterionTypes.CPE
		rng     cperangeTypes.Range
		bounded bool
	)
	for _, a := range cna.Affected {
		for _, v := range a.Versions {
			switch {
			case v.LessThan != nil && *v.LessThan != "":
				rng.LessThan = *v.LessThan
				bounded = true
			case v.LessThanOrEqual != nil && *v.LessThanOrEqual != "":
				rng.LessEqual = *v.LessThanOrEqual
				bounded = true
			default:
				if v.Version != "" && v.Version != "0" {
					matches = append(matches, cpecriterionTypes.CPE(fmt.Sprintf(versionCPE, v.Version)))
				}
				continue
			}
			if v.Version != "" && v.Version != "0" {
				rng.GreaterEqual = v.Version
			}
		}
		for _, c := range a.CPEs {
			matches = appendCPEMatch(matches, fetched.CVEMetadata.CVEID, c)
		}
	}
	if bounded {
		rng.Type = cperangeTypes.RangeTypeSEMVER
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.CVEMetadata.CVEID),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:    vulnerabilityContentTypes.VulnerabilityID(fetched.CVEMetadata.CVEID),
				Title: cna.Title,
				Description: func() string {
					for _, d := range cna.Descriptions {
						if d.Lang == "en" {
							return d.Value
						}
					}
					return ""
				}(),
				Severity: func() []severityTypes.Severity {
					var ss []severityTypes.Severity
					for _, m := range cna.Metrics {
						if m.Other.Content.Text == "" || m.Other.Content.Text == "n/a" {
							continue
						}
						ss = append(ss, severityTypes.Severity{
							Type:   severityTypes.SeverityTypeVendor,
							Source: sourceLabel,
							Vendor: &m.Other.Content.Text,
						})
					}
					return ss
				}(),
				CWE: func() []cweTypes.CWE {
					var cs []string
					for _, p := range cna.ProblemTypes {
						for _, d := range p.Descriptions {
							if d.CWEID != nil && *d.CWEID != "" {
								cs = append(cs, *d.CWEID)
							}
						}
					}
					if len(cs) == 0 {
						return nil
					}
					return []cweTypes.CWE{{Source: sourceLabel, CWE: cs}}
				}(),
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0, len(cna.References))
					for _, ref := range cna.References {
						if ref.URL == "" {
							continue
						}
						rs = append(rs, referenceTypes.Reference{
							Source: sourceLabel,
							URL:    ref.URL,
						})
					}
					if len(rs) == 0 {
						return nil
					}
					return rs
				}(),
				// The CVE Record Format records the ASF serves carry no
				// datePublished and no "public" timeline entry, so there is no
				// publication date to map.
			},
			Segments: segments(matches, bounded),
		}},
		Detections: detections(matches, rng, bounded),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.ApacheHTTPDJSON,
			Raws: raws,
		},
	}
}

// appendCPEMatch adds an entry from affected[].cpes to the criterion's explicit
// match list. The criterion is already pinned to the product by productCPE, so
// an entry carrying no concrete version adds nothing — and as a CPEMatch it
// would match every version and quietly defeat the criterion's Range. Such an
// entry is dropped when it merely restates productCPE, and reported otherwise.
func appendCPEMatch(matches []cpecriterionTypes.CPE, id, c string) []cpecriterionTypes.CPE {
	wfn, err := naming.UnbindFS(c)
	if err != nil {
		slog.Warn("skip unparseable cpe", "cve", id, "cpe", c, "error", err)
		return matches
	}

	switch wfn.GetString(common.AttributeVersion) {
	case "ANY", "NA":
		if c != productCPE {
			slog.Warn("skip cpe without a concrete version", "cve", id, "cpe", c)
		}
		return matches
	default:
		return append(matches, cpecriterionTypes.CPE(c))
	}
}

func segments(matches []cpecriterionTypes.CPE, bounded bool) []segmentTypes.Segment {
	if len(matches) == 0 && !bounded {
		return nil
	}
	return []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}}
}

func detections(matches []cpecriterionTypes.CPE, rng cperangeTypes.Range, bounded bool) []detectionTypes.Detection {
	if len(matches) == 0 && !bounded {
		return nil
	}

	c := cpecriterionTypes.Criterion{
		Vulnerable: true,
		CPE:        productCPE,
		CPEMatches: matches,
	}
	if bounded {
		c.Range = &rng
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{{
					Type: criterionTypes.CriterionTypeCPE,
					CPE:  &c,
				}},
			},
		}},
	}}
}
