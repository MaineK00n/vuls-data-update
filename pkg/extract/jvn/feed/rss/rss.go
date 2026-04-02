package rss

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	cpePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
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
	fetchTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/rss"
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
		dir: filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "rss"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract JVN Feed RSS")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched fetchTypes.Item
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		data, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		splitted, err := util.Split(string(data.ID), "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "JVNDB-yyyy-\\d{6}", data.ID)
		}

		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.JVNFeedRSS,
		Name: new("Japan Vulnerability Notes: JVN Feed RSS"),
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

func extract(fetched fetchTypes.Item, raws []string) (dataTypes.Data, error) {
	// Build CVSS severity
	var ss []severityTypes.Severity
	for _, cvss := range fetched.CVSS {
		if cvss.Vector == "" {
			continue
		}
		switch cvss.Version {
		case "2.0":
			v2, err := v2Types.Parse(cvss.Vector)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "parse cvss v2 %q", cvss.Vector)
			}
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: "jvndb.jvn.jp",
				CVSSv2: v2,
			})
		case "3.0":
			v30, err := v30Types.Parse(cvss.Vector)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "parse cvss v3.0 %q", cvss.Vector)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  "jvndb.jvn.jp",
				CVSSv30: v30,
			})
		case "3.1":
			v31, err := v31Types.Parse(cvss.Vector)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "parse cvss v3.1 %q", cvss.Vector)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  "jvndb.jvn.jp",
				CVSSv31: v31,
			})
		default:
			return dataTypes.Data{}, errors.Errorf("unknown CVSS version %q, vector %q", cvss.Version, cvss.Vector)
		}
	}

	// Build CWE from references (entries with ID starting with "CWE-" and no Source)
	var cweIDs []string
	for _, ref := range fetched.References {
		if ref.Source == "" && strings.HasPrefix(ref.ID, "CWE-") {
			cweIDs = append(cweIDs, ref.ID)
		}
	}
	var cwes []cweTypes.CWE
	if len(cweIDs) > 0 {
		cwes = []cweTypes.CWE{{
			Source: "jvndb.jvn.jp",
			CWE:    cweIDs,
		}}
	}

	// Build references (exclude CWE entries)
	var refs []referenceTypes.Reference
	for _, ref := range fetched.References {
		if ref.Source == "" || ref.Text == "" {
			continue
		}
		refs = append(refs, referenceTypes.Reference{
			Source: "jvndb.jvn.jp",
			URL:    ref.Text,
		})
	}

	// Build CPE-based detections (convert CPE 2.2 URI to CPE 2.3 FS format)
	var criterions []criterionTypes.Criterion
	for _, cpe := range fetched.CPE {
		if cpe.Text == "" {
			continue
		}
		wfn, err := naming.UnbindURI(cpe.Text)
		if err != nil {
			slog.Warn("skip invalid CPE URI", slog.String("cpe", cpe.Text), slog.Any("err", err))
			continue
		}
		criterions = append(criterions, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeCPE,
					CPE:  new(cpePackageTypes.CPE(naming.BindToFS(wfn))),
				},
			},
		})
	}

	var segments []segmentTypes.Segment
	var detections []detectionTypes.Detection
	if len(criterions) > 0 {
		segments = []segmentTypes.Segment{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		}}
		detections = []detectionTypes.Detection{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
			Conditions: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: criterions,
				},
			}},
		}}
	}

	// Build vulnerabilities from CVE references (merge references for same CVE ID)
	vulnMap := make(map[string]vulnerabilityTypes.Vulnerability)
	for _, ref := range fetched.References {
		if !strings.HasPrefix(ref.ID, "CVE-") {
			continue
		}
		if _, ok := vulnMap[ref.ID]; !ok {
			vulnMap[ref.ID] = vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(ref.ID),
				},
				Segments: segments,
			}
		}
		if ref.Text != "" {
			v := vulnMap[ref.ID]
			v.Content.References = append(v.Content.References, referenceTypes.Reference{
				Source: "jvndb.jvn.jp",
				URL:    ref.Text,
			})
			vulnMap[ref.ID] = v
		}
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.Identifier),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.Identifier),
				Title:       fetched.Title,
				Description: fetched.Description,
				Severity:    ss,
				CWE:         cwes,
				References:  refs,
				Published:   utiltime.Parse([]string{time.RFC3339, "2006-01-02T15:04-07:00"}, fetched.Issued),
				Modified:    utiltime.Parse([]string{time.RFC3339, "2006-01-02T15:04-07:00"}, fetched.Modified),
			},
			Segments: segments,
		}},
		Vulnerabilities: slices.Collect(maps.Values(vulnMap)),
		Detections:      detections,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.JVNFeedRSS,
			Raws: raws,
		},
	}, nil
}
