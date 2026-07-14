package oval

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	oval "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/oval"
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

type extractor struct {
	ovalDir string
	r       *utiljson.JSONReader
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract AlmaLinux OVAL")

	br := utiljson.NewJSONReader()

	majorEntries, err := os.ReadDir(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}
	for _, majorEntry := range majorEntries {
		if !majorEntry.IsDir() || majorEntry.Name() == ".git" {
			continue
		}

		if err := filepath.WalkDir(filepath.Join(args, majorEntry.Name(), "definitions"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			e := extractor{
				ovalDir: args,
				r:       br.Copy(),
			}

			var def oval.Definition
			if err := e.r.Read(path, e.ovalDir, &def); err != nil {
				return errors.Wrapf(err, "read %s", path)
			}

			switch def.Class {
			case "patch":
				extracted, err := e.extract(majorEntry.Name(), def)
				if err != nil {
					return errors.Wrapf(err, "extract %s", path)
				}

				ss, err := util.Split(string(extracted.ID), "-", ":")
				if err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALSA-<year>:<ID>", extracted.ID)
				}
				if _, err := time.Parse("2006", ss[1]); err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALSA-<year>:<ID>", extracted.ID)
				}

				if _, err := os.Stat(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID))); err == nil {
					f, err := os.Open(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
					if err != nil {
						return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
					}
					defer f.Close()

					var base dataTypes.Data
					if err := json.UnmarshalRead(f, &base); err != nil {
						return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
					}

					extracted.Merge(base)
				}

				if err := util.Write(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
				}

				return nil
			default:
				return errors.Errorf("unexpected oval definition class. expected: %q, actual: %q", []string{"patch"}, def.Class)
			}
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(args, majorEntry.Name(), "definitions"))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.AlmaOVAL,
		Name: new("AlmaLinux OVAL"),
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

func (e extractor) extract(major string, def oval.Definition) (dataTypes.Data, error) {
	id, err := func() (string, error) {
		var ids []string
		for _, r := range def.Metadata.Reference {
			if r.Source == "ALSA" {
				ids = append(ids, r.RefID)
			}
		}
		switch ids := util.Unique(ids); len(ids) {
		case 1:
			return ids[0], nil
		default:
			return "", errors.Errorf("unexpected ALSA reference count. expected: %q, actual: %q", "1", ids)
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "parse definition id")
	}

	ds, err := func() ([]detectionTypes.Detection, error) {
		ca, err := e.walkCriteria(major, def.Criteria)
		if err != nil {
			return nil, errors.Wrap(err, "walk criteria")
		}

		if !hasCriterion(ca) {
			return nil, nil
		}

		return []detectionTypes.Detection{{
			Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, major)),
			Conditions: []conditionTypes.Condition{{
				Criteria: postWalkCriteria(ca),
			}},
		}}, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk detections")
	}

	segs := func() []segmentTypes.Segment {
		var ss []segmentTypes.Segment
		for _, d := range ds {
			ss = append(ss, segmentTypes.Segment{Ecosystem: d.Ecosystem})
		}
		return ss
	}()

	vs, err := func() ([]vulnerabilityTypes.Vulnerability, error) {
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(def.Metadata.Advisory.Cve))
		for _, cve := range def.Metadata.Advisory.Cve {
			ss, err := func() ([]severityTypes.Severity, error) {
				var ss []severityTypes.Severity
				if cve.Impact != "" {
					ss = append(ss, severityTypes.Severity{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "packager@almalinux.org",
						Vendor: &cve.Impact,
					})
				}
				if cve.Cvss3 != "" {
					switch vector := strings.TrimSpace(cve.Cvss3); {
					case strings.HasPrefix(vector, "CVSS:3.0"):
						v30, err := cvssV30Types.Parse(vector)
						if err != nil {
							return nil, errors.Wrap(err, "parse cvss3")
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv30,
							Source:  "packager@almalinux.org",
							CVSSv30: v30,
						})
					case strings.HasPrefix(vector, "CVSS:3.1"):
						v31, err := cvssV31Types.Parse(vector)
						if err != nil {
							return nil, errors.Wrap(err, "parse cvss3")
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv31,
							Source:  "packager@almalinux.org",
							CVSSv31: v31,
						})
					default:
						return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "CVSS:3.[01]/<vector>", cve.Cvss3)
					}
				}
				return ss, nil
			}()
			if err != nil {
				return nil, errors.Wrap(err, "walk severity")
			}

			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID:       vulnerabilityContentTypes.VulnerabilityID(cve.Text),
					Severity: ss,
					CWE: func() []cweTypes.CWE {
						if cve.Cwe == "" {
							return nil
						}
						return []cweTypes.CWE{{
							Source: "packager@almalinux.org",
							CWE:    []string{cve.Cwe},
						}}
					}(),
					References: []referenceTypes.Reference{{
						Source: "packager@almalinux.org",
						URL:    cve.Href,
					}},
					Published: utiltime.Parse([]string{"20060102"}, cve.Public),
				},
				Segments: segs,
			})
		}
		return vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk vulnerability")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(id),
				Title:       strings.TrimSpace(def.Metadata.Title),
				Description: strings.TrimSpace(def.Metadata.Description),
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "packager@almalinux.org",
					Vendor: &def.Metadata.Advisory.Severity,
				}},
				References: func() []referenceTypes.Reference {
					refs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference)+len(def.Metadata.Advisory.Bugzilla))
					for _, r := range def.Metadata.Reference {
						refs = append(refs, referenceTypes.Reference{
							Source: "packager@almalinux.org",
							URL:    r.RefURL,
						})
					}
					for _, b := range def.Metadata.Advisory.Bugzilla {
						refs = append(refs, referenceTypes.Reference{
							Source: "packager@almalinux.org",
							URL:    b.Href,
						})
					}
					return refs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
				Modified:  utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Updated.Date),
			},
			Segments: segs,
		}},
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.AlmaOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}

func (e extractor) walkCriteria(major string, criteria oval.Criteria) (criteriaTypes.Criteria, error) {
	var ca criteriaTypes.Criteria
	switch criteria.Operator {
	case "OR":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("unexpected criteria operator. expected: %q, actual: %q", []string{"OR", "AND"}, criteria.Operator)
	}

	for _, ovalCa := range criteria.Criterias {
		cca, err := e.walkCriteria(major, ovalCa)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "walk criteria")
		}
		switch {
		case len(cca.Criterias) == 0 && len(cca.Criterions) == 0:
		default:
			ca.Criterias = append(ca.Criterias, cca)
		}
	}

	cca, err := e.walkCriterions(ca, major, criteria.Criterions)
	if err != nil {
		return criteriaTypes.Criteria{}, errors.Wrap(err, "walk criterions")
	}
	return cca, nil
}

func (e extractor) walkCriterions(ca criteriaTypes.Criteria, major string, ovalCns []oval.Criterion) (criteriaTypes.Criteria, error) {
	var next []oval.Criterion

	for _, ovalCn := range ovalCns {
		var t1 oval.RpminfoTest
		if err := e.read(major, "tests", "rpminfo_test", ovalCn.TestRef, &t1); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("tests", "rpminfo_test", ovalCn.TestRef))
			}
			next = append(next, ovalCn)
			continue
		}

		switch {
		case strings.Contains(t1.Comment, " is earlier than "):
			var o oval.RpminfoObject
			if err := e.read(major, "objects", "rpminfo_object", t1.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "rpminfo_object", t1.Object.ObjectRef))
			}

			var s oval.RpminfoState
			if err := e.read(major, "states", "rpminfo_state", t1.State.StateRef, &s); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("states", "rpminfo_state", t1.State.StateRef))
			}

			if s.Evr.Text == "" {
				return criteriaTypes.Criteria{}, errors.New("evr is empty")
			}
			switch s.Evr.Operation {
			case "less than":
				ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
						Package: packageTypes.Package{
							Type: packageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{
								Name: o.Name,
								Architectures: func() []string {
									if s.Arch.Text == "" {
										return nil
									}
									return strings.Split(s.Arch.Text, "|")
								}(),
							},
						},
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Range: []rangeTypes.Range{{LessThan: s.Evr.Text}},
							Fixed: []string{s.Evr.Text},
						},
					},
				})
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("unexpected evr operation. expected: %q, actual: %q", []string{"less than"}, s.Evr.Operation)
			}
		case strings.Contains(t1.Comment, " is signed with AlmaLinux OS "):
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{
				"<package> is earlier than <version>",
				"<package> is signed with AlmaLinux OS <version> key",
			}, t1.Comment)
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t2 oval.Textfilecontent54Test
		if err := e.read(major, "tests", "textfilecontent54_test", ovalCn.TestRef, &t2); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("tests", "textfilecontent54_test", ovalCn.TestRef))
			}
			next = append(next, ovalCn)
			continue
		}

		switch {
		case strings.HasPrefix(t2.Comment, "Module ") && strings.HasSuffix(t2.Comment, " is enabled"):
			var o oval.Textfilecontent54Object
			if err := e.read(major, "objects", "textfilecontent54_object", t2.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "textfilecontent54_object", t2.Object.ObjectRef))
			}

			// <ind-def:pattern operation="pattern match">\[perl\-FCGI\][\w\W]*</ind-def:pattern>
			remaining, found := strings.CutPrefix(o.Pattern.Text, `\[`)
			if !found {
				return criteriaTypes.Criteria{}, errors.Errorf(`unexpected module pattern at prefix. expected: \[, actual: %s`, o.Pattern.Text)
			}
			remaining, found = strings.CutSuffix(remaining, `\][\w\W]*`)
			if !found {
				return criteriaTypes.Criteria{}, errors.Errorf(`unexpected module pattern at suffix. expected: \][\w\W]*, actual: %s`, remaining)
			}
			module := strings.ReplaceAll(remaining, `\`, "")

			var s oval.Textfilecontent54State
			if err := e.read(major, "states", "textfilecontent54_state", t2.State.StateRef, &s); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("states", "textfilecontent54_state", t2.State.StateRef))
			}

			// <ind-def:text operation="pattern match">\nstream\s*=\s*2\.8\b[\w\W]*\nstate\s*=\s*(enabled|1|true)|\nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*2\.8\b</ind-def:text>
			// To extract "stream" value, the regexp pattern of reversed order ("state" at the beginning) is also considered,
			// e.g. \nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*2.8\b|\nstream\s*=\s*2.8\b[\w\W]*\nstate\s*=\s*(enabled|1|true)
			var ss []string
			for s := range strings.SplitSeq(s.Text.Text, `\n`) {
				if s == "" {
					continue
				}

				lhs, rhs, ok := strings.Cut(s, `\s*=\s*`)
				if !ok {
					return criteriaTypes.Criteria{}, errors.Errorf("unexpected pattern. expected: %s, actual: %s", `<entry>\s*=\s*<value>`, s)
				}
				if lhs == "stream" {
					ss = append(ss, strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(rhs, "|"), `[\w\W]*`), `\b`), `\`, ""))
				}
			}

			switch ss := util.Unique(ss); len(ss) {
			case 1:
				var f func(ca criteriaTypes.Criteria, modularitylabel string) error
				f = func(ca criteriaTypes.Criteria, modularitylabel string) error {
					for i := range ca.Criterias {
						if err := f(ca.Criterias[i], modularitylabel); err != nil {
							return errors.Wrap(err, "add modularitylabel in criteria")
						}
					}
					for i := range ca.Criterions {
						switch ca.Criterions[i].Type {
						case criterionTypes.CriterionTypeVersion:
							ca.Criterions[i].Version.Package.Binary.Name = fmt.Sprintf("%s::%s", modularitylabel, ca.Criterions[i].Version.Package.Binary.Name)
						default:
							return errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion}, ca.Criterions[i].Type)
						}
					}
					return nil
				}
				if err := f(ca, fmt.Sprintf("%s:%s", module, ss[0])); err != nil {
					return criteriaTypes.Criteria{}, errors.Wrap(err, "add modularitylabel")
				}
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("stream cannot be determined to a single value. values: %v, text: %s", ss, s.Text.Text)
			}
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"Module <module name>:<module stream> is enabled"}, t2.Comment)
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t3 oval.RpmverifyfileTest
		if err := e.read(major, "tests", "rpmverifyfile_test", ovalCn.TestRef, &t3); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("tests", "rpmverifyfile_test", ovalCn.TestRef))
			}
			next = append(next, ovalCn)
			continue
		}

		switch {
		case t3.Comment == "AlmaLinux must be installed":
		case strings.HasPrefix(t3.Comment, "AlmaLinux ") && strings.HasSuffix(t3.Comment, " is installed"):
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"AlmaLinux must be installed", "AlmaLinux <version> is installed"}, t3.Comment)
		}
	}

	if len(next) > 0 {
		return criteriaTypes.Criteria{}, errors.Errorf("%q is not found in %q", func() []string {
			rs := make([]string, 0, len(next))
			for _, ovalCn := range next {
				rs = append(rs, ovalCn.TestRef)
			}
			return rs
		}(), []string{"rpminfo_test", "textfilecontent54_test", "rpmverifyfile_test"})
	}
	return ca, nil
}

func hasCriterion(ca criteriaTypes.Criteria) bool {
	if len(ca.Criterions) > 0 {
		return true
	}
	return slices.ContainsFunc(ca.Criterias, hasCriterion)
}

func postWalkCriteria(ca criteriaTypes.Criteria) criteriaTypes.Criteria {
	if len(ca.Criterias) != 1 || len(ca.Criterions) != 0 {
		return ca
	}
	return postWalkCriteria(ca.Criterias[0])
}

func (e extractor) read(major, class, family, id string, v any) error {
	if err := e.r.Read(filepath.Join(e.ovalDir, major, class, family, fmt.Sprintf("%s.json", id)), e.ovalDir, v); err != nil {
		return errors.Wrapf(err, "read %s %s", class, family)
	}
	return nil
}
