package securityadvisories

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	nginxSecurityAdvisories "github.com/MaineK00n/vuls-data-update/pkg/fetch/nginx/security-advisories"
)

// source names the publisher of every content the page carries.
const source = "nginx.org"

const (
	// nginxCPE is the CPE the advisories describe. NVD files nginx releases
	// under the f5 vendor regardless of when they were published, including
	// the pre-F5 ones.
	nginxCPE = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	// windowsCPE qualifies the "nginx/Windows" entries. The Windows build is
	// expressed as a platform the vulnerable nginx runs on, not as a variant
	// of the nginx CPE, which is also how NVD publishes these advisories.
	windowsCPE = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
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
		dir: filepath.Join(util.CacheDir(), "extract", "nginx", "security-advisories"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract nginx Security Advisories")
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
		var fetched nginxSecurityAdvisories.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
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
		ID:   sourceTypes.NginxSecurityAdvisories,
		Name: func() *string { s := "nginx Security Advisories"; return &s }(),
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

func extract(fetched nginxSecurityAdvisories.Advisory, raws []string) (dataTypes.Data, error) {
	ds, err := detections(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "detections")
	}

	data := dataTypes.Data{
		ID:         dataTypes.RootID(fetched.ID),
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.NginxSecurityAdvisories,
			Raws: raws,
		},
	}

	// The page identifies almost every entry by its CVE, which becomes a
	// Vulnerability carrying nginx's statement about it. The one entry that
	// predates its CVE assignment is identified by a Core Security advisory ID
	// instead; being advisory-class, it becomes an Advisory, mirroring how the
	// paloalto extractor places a PAN-SA root.
	ss, ms, rs := severities(fetched), mitigations(fetched), references(fetched)

	if strings.HasPrefix(fetched.ID, "CVE-") {
		data.Vulnerabilities = []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:          vulnerabilityContentTypes.VulnerabilityID(fetched.ID),
				Title:       fetched.Title,
				Severity:    ss,
				Mitigations: ms,
				References:  rs,
			},
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}}
		return data, nil
	}

	data.Advisories = []advisoryTypes.Advisory{{
		Content: advisoryContentTypes.Content{
			ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
			Title:       fetched.Title,
			Severity:    ss,
			Mitigations: ms,
			References:  rs,
		},
		Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
	}}
	return data, nil
}

// severities carries the page's own severity word ("none", "minor", "low",
// "medium", "major") as a vendor severity. The page publishes no CVSS.
func severities(fetched nginxSecurityAdvisories.Advisory) []severityTypes.Severity {
	if fetched.Severity == "" {
		return nil
	}
	return []severityTypes.Severity{{
		Type:   severityTypes.SeverityTypeVendor,
		Source: source,
		Vendor: &fetched.Severity,
	}}
}

// references keeps every link of the entry: the advisory article or mailing
// list post, the CVE record, any CERT note, and the patch downloads.
func references(fetched nginxSecurityAdvisories.Advisory) []referenceTypes.Reference {
	refs := make([]referenceTypes.Reference, 0, len(fetched.References)+2*len(fetched.Patches))
	for _, r := range fetched.References {
		refs = append(refs, referenceTypes.Reference{Source: source, URL: r.URL})
	}
	for _, p := range fetched.Patches {
		refs = append(refs, referenceTypes.Reference{Source: source, URL: p.URL})
		if p.SignatureURL != "" {
			refs = append(refs, referenceTypes.Reference{Source: source, URL: p.SignatureURL})
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// mitigations records the patches offered for releases that never got a fixed
// build. The applicability remark ("(for 1.9.13-1.11.0)") is what tells the two
// patches of an entry apart, so it is kept alongside the URL.
func mitigations(fetched nginxSecurityAdvisories.Advisory) []remediationTypes.Remediation {
	if len(fetched.Patches) == 0 {
		return nil
	}
	rs := make([]remediationTypes.Remediation, 0, len(fetched.Patches))
	for _, p := range fetched.Patches {
		d := p.URL
		if p.Note != "" {
			d = fmt.Sprintf("%s %s", p.URL, p.Note)
		}
		rs = append(rs, remediationTypes.Remediation{Source: source, Description: d})
	}
	return rs
}

// detections turns the "Vulnerable:" / "Not vulnerable:" lists into criteria.
// Each vulnerable entry becomes one child criteria of a top level OR, so the
// entries that apply to the Windows build only can carry their platform without
// constraining the others.
func detections(fetched nginxSecurityAdvisories.Advisory) ([]detectionTypes.Detection, error) {
	fixes, err := parseNotVulnerable(fetched.NotVulnerable)
	if err != nil {
		return nil, errors.Wrap(err, "parse not vulnerable")
	}

	cas := make([]criteriaTypes.Criteria, 0, len(fetched.Vulnerable))
	for _, s := range fetched.Vulnerable {
		r, err := parseVulnerable(s)
		if err != nil {
			return nil, errors.Wrap(err, "parse vulnerable")
		}

		var cns []criterionTypes.Criterion
		switch {
		case r.All:
			// Every release is affected and none is fixed: a bare criterion
			// with no range, matching any nginx version.
			cns = []criterionTypes.Criterion{nginxCriterion(nil)}
		default:
			is := affectedIntervals(r, fixes)
			cns = make([]criterionTypes.Criterion, 0, len(is))
			for _, i := range is {
				cns = append(cns, nginxCriterion(&i))
			}
		}

		ca := criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: cns}
		if r.Windows {
			ca = criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					ca,
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								// The platform is a precondition, not the
								// vulnerable component.
								Vulnerable: false,
								CPE:        ccTypes.CPE(windowsCPE),
							},
						}},
					},
				},
			}
		}
		cas = append(cas, ca)
	}

	if len(cas) == 0 {
		return nil, nil
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: cas,
			},
		}},
	}}, nil
}

// nginxCriterion builds the criterion for one affected interval. A nil interval
// means every version is affected, which is a criterion with no range.
func nginxCriterion(i *interval) criterionTypes.Criterion {
	c := ccTypes.Criterion{
		Vulnerable: true,
		CPE:        ccTypes.CPE(nginxCPE),
	}

	if i != nil {
		c.Range = &ccRangeTypes.Range{
			Type:         ccRangeTypes.RangeTypeVersion,
			GreaterEqual: i.GreaterEqual.String(),
		}
		switch {
		case i.LessThan != nil:
			c.Range.LessThan = i.LessThan.String()
		case i.LessEqual != nil:
			c.Range.LessEqual = i.LessEqual.String()
		}
		if i.Fixed != nil {
			c.Fixed = []string{i.Fixed.String()}
		}
	}

	return criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &c}
}
