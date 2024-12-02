package oracle

import (
	"fmt"
	"io/fs"
	"log"
	"os"
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
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle"
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
	inputDir string
	r        *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "oracle"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Oracle")

	if err := filepath.WalkDir(filepath.Join(inputDir, "definitions"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		e := extractor{
			inputDir: inputDir,
			r:        utiljson.NewJSONReader(),
		}
		var def oracle.Definition
		if err := e.r.Read(path, e.inputDir, &def); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		data, err := e.extract(def)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		ss := strings.Split(string(data.ID), "-")
		if len(ss) < 3 || ss[0] != "ELSA" {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "ELSA-<year>-<ID>", data.ID)
		}
		year := ss[1]

		if err := util.Write(filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", inputDir)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Oracle,
		Name: func() *string { t := "Oracle Linux OVAL"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(inputDir)
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

func (e extractor) extract(def oracle.Definition) (dataTypes.Data, error) {
	id, _, ok := strings.Cut(strings.TrimSpace(def.Metadata.Title), ":")
	if !ok {
		return dataTypes.Data{}, errors.Errorf("unexpected title format. expected: %q, actual: %q", "<Advisory ID>: ...", def.Metadata.Title)
	}

	ds, err := e.collectPackages(def.Criteria)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collectPackages, definition: %s", def.ID)
	}

	segs := func() []segmentTypes.Segment {
		ss := make([]segmentTypes.Segment, 0, len(ds))
		for _, d := range ds {
			ss = append(ss, segmentTypes.Segment{Ecosystem: d.Ecosystem})
		}
		return ss
	}()

	vs, err := func() ([]vulnerabilityTypes.Vulnerability, error) {
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(def.Metadata.Advisory.Cve))
		for _, cve := range def.Metadata.Advisory.Cve {
			var ss []severityTypes.Severity
			if cve.CVSS2 != "" {
				_, rhs, _ := strings.Cut(cve.CVSS2, "/")
				v2, err := cvssV2Types.Parse(rhs)
				if err != nil {
					if !strings.Contains(rhs, "AC:N") { // e.g. AV:N/AC:N/Au:N/C:N/I:N/A:N ; oval:com.oracle.elsa:def:20100046 CVE-2009-2910
						return nil, errors.Wrap(err, "parse cvss2")
					}
				} else {
					ss = append(ss, severityTypes.Severity{
						Type:   severityTypes.SeverityTypeCVSSv2,
						Source: "linux.oracle.com/security",
						CVSSv2: v2,
					})
				}
			}
			if cve.CVSS3 != "" {
				_, rhs, _ := strings.Cut(cve.CVSS3, "/")
				switch {
				case strings.HasPrefix(rhs, "CVSS:3.0"):
					v30, err := cvssV30Types.Parse(rhs)
					if err != nil {
						if !strings.Contains(rhs, "AC:N") { // e.g. CVSS:3.0/AV:N/AC:N/PR:N/UI:N/S:U/C:N/I:N/A:N ; oval:com.oracle.elsa:def:20130727 CVE-2013-1798
							return nil, errors.Wrap(err, "parse cvss3")
						}
					} else {
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv30,
							Source:  "linux.oracle.com/security",
							CVSSv30: v30,
						})
					}
				case strings.HasPrefix(rhs, "CVSS:3.1"):
					v31, err := cvssV31Types.Parse(rhs)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3")
					}
					ss = append(ss, severityTypes.Severity{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "linux.oracle.com/security",
						CVSSv31: v31,
					})
				default:
					return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.CVSS3)
				}
			}

			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID:       vulnerabilityContentTypes.VulnerabilityID(cve.Text),
					Severity: ss,
					References: []referenceTypes.Reference{{
						Source: "linux.oracle.com/security",
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
					Source: "linux.oracle.com/security",
					Vendor: &def.Metadata.Advisory.Severity}},
				References: func() []referenceTypes.Reference {
					refs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference))
					for _, r := range def.Metadata.Reference {
						refs = append(refs, referenceTypes.Reference{
							Source: "linux.oracle.com/security",
							URL:    r.RefURL,
						})
					}
					return refs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
			},
			Segments: segs,
		}},
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Oracle,
			Raws: e.r.Paths(),
		},
	}, nil
}

type ovalPackage struct {
	major           string
	name            string
	fixedVersion    string
	modularityLabel string
	arch            string
}

func (e extractor) collectPackages(criteria oracle.Criteria) ([]detectionTypes.Detection, error) {
	pkgs, err := e.evalCriteria(criteria)
	if err != nil {
		return nil, errors.Wrapf(err, "eval criteria")
	}

	m := make(map[ovalPackage][]string)
	for _, p := range pkgs {
		m[ovalPackage{
			major:           p.major,
			name:            p.name,
			fixedVersion:    p.fixedVersion,
			modularityLabel: p.modularityLabel,
		}] = append(m[ovalPackage{
			major:           p.major,
			name:            p.name,
			fixedVersion:    p.fixedVersion,
			modularityLabel: p.modularityLabel,
		}], p.arch)
	}

	// major version -> criterion
	mm := make(map[string][]criterionTypes.Criterion)
	for p, as := range m {
		mm[p.major] = append(mm[p.major], criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeBinary,
					Binary: &binaryPackageTypes.Package{
						Name: func() string {
							switch p.modularityLabel {
							case "":
								return p.name
							default:
								return fmt.Sprintf("%s::%s", p.modularityLabel, p.name)
							}
						}(),
						Architectures: as,
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{LessThan: p.fixedVersion}},
					Fixed: []string{p.fixedVersion},
				},
			},
		})
	}

	ds := make([]detectionTypes.Detection, 0, len(mm))
	for v, cs := range mm {
		ds = append(ds, detectionTypes.Detection{
			Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, v)),
			Conditions: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cs,
				},
			}},
		})
	}
	return ds, nil
}

func (e extractor) evalCriteria(criteria oracle.Criteria) ([]ovalPackage, error) {
	// Exclude patterns that do not exists in oracle oval data and don't implement them, YAGNI.
	// With these constraints, we can ignore Criteria.Operator (AND or OR) to extract package information.
	switch {
	case criteria.Operator == "OR" && len(criteria.Criterions) > 0:
		return nil, errors.Errorf("criterions under OR criteria MUST not exist")
	case criteria.Operator == "OR" && len(criteria.Criterias) == 0:
		return nil, errors.Errorf("criterias under OR criteria MUST exist")
	case criteria.Operator == "AND" && len(criteria.Criterias) > 1:
		return nil, errors.Errorf("criterias under AND-criteria MUST be < 2")
	}

	var pkgs []ovalPackage

	for _, ca := range criteria.Criterias {
		ps, err := e.evalCriteria(ca)
		if err != nil {
			return nil, errors.Wrap(err, "eval criteria")
		}
		pkgs = append(pkgs, ps...)
	}

	// If this criteria is AND and without child criterias case. Add base (ANY) one
	if criteria.Operator == "AND" && len(criteria.Criterias) == 0 {
		pkgs = append(pkgs, ovalPackage{})
	}

	if err := e.evalCriterions(pkgs, criteria.Criterions); err != nil {
		return nil, errors.Wrap(err, "eval criterions")
	}
	return pkgs, nil
}

func (e extractor) evalCriterions(pkgs []ovalPackage, criterions []oracle.Criterion) error {
	for _, c := range criterions {
		test, err := e.readRpminfoTest(c.TestRef)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Wrapf(err, "read rpminfo_test file. ref: %s", c.TestRef)
		}

		if err == nil {
			obj, err := e.readRpminfoObj(test.Object.ObjectRef)
			if err != nil {
				return errors.Wrapf(err, "read rpminfo object. ref: %s", test.Object.ObjectRef)
			}
			state, err := e.readRpminfoState(test.State.StateRef)
			if err != nil {
				return errors.Wrapf(err, "read rpminfo state. ref: %s", test.State.StateRef)
			}

			switch obj.Name {
			case "oraclelinux-release":
				switch {
				case state.Version != nil:
					for i := range pkgs {
						pkgs[i].major = strings.TrimPrefix(state.Version.Text, "^")
					}
				case state.Arch != nil:
					for i := range pkgs {
						pkgs[i].arch = state.Arch.Text
					}
				default:
					return errors.Errorf("invalid combination, obj %+v and state %+v", obj, state)
				}
			default:
				switch {
				case state.Evr != nil:
					if state.Evr.Operation != "less than" {
						return errors.Errorf("unexpected evr operation: %s", state.Evr.Operation)
					}
					for i := range pkgs {
						pkgs[i].name = obj.Name
						pkgs[i].fixedVersion = state.Evr.Text
					}
				case state.SignatureKeyid != nil:
				case state.Release != nil:
					// <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:com.oracle.elsa:ste:20163515002" version="501">
					//   <release operation="pattern match">ksplice</release>
					// </rpminfo_state>
					// ksplice information *seems* included in version information, e.g. 2:2.17-106.0.1.ksplice1.el7_2.4
				default:
					return errors.Errorf("invalid combination, obj %+v and state %+v", obj, state)
				}
			}
		} else {
			test, err := e.readTextfilecontent54Test(c.TestRef)
			if err != nil {
				return errors.Wrapf(err, "read textfilecontent54_test. ref: %s", c.TestRef)
			}

			obj, err := e.readTextfilecontent54Obj(test.Object.ObjectRef)
			if err != nil {
				return errors.Wrapf(err, "read textfilecontent54_object. ref: %s", test.Object.ObjectRef)
			}
			state, err := e.readTextfilecontent54OState(test.State.StateRef)
			if err != nil {
				return errors.Wrapf(err, "read textfilecontent54_state. ref: %s", test.State.StateRef)
			}

			if !strings.HasPrefix(obj.Filepath.Text, "/etc/dnf/modules.d/") {
				continue
			}

			// <ind-def:pattern operation="pattern match">\[container\-tools\][\w\W]*</ind-def:pattern>
			remaining, found := strings.CutPrefix(obj.Pattern.Text, `\[`)
			if !found {
				return errors.Errorf(`unexpected module pattern at prefix. expected: \[, actual: %s`, obj.Pattern.Text)
			}
			remaining, found = strings.CutSuffix(remaining, `\][\w\W]*`)
			if !found {
				return errors.Errorf(`unexpected module pattern at suffix. expected: \][\w\W]*, actual: %s`, remaining)
			}
			module := strings.ReplaceAll(remaining, `\`, "")

			// <ind-def:text operation="pattern match">\nstream\s*=\s*ol8\b[\w\W]*\nstate\s*=\s*(enabled|1|true)|\nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*ol8\b</ind-def:text>
			// To extract "stream" value, the regexp pattern of reversed order ("state" at the beginning) is also considered,
			// e.g. \nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*ol8\b|\nstream\s*=\s*ol8\b[\w\W]*\nstate\s*=\s*(enabled|1|true)
			var ss []string
			for _, s := range strings.Split(state.Text.Text, `\n`) {
				if s == "" {
					continue
				}

				lhs, rhs, ok := strings.Cut(s, `\s*=\s*`)
				if !ok {
					return errors.Errorf("unexpected pattern. expected: %s, actual: %s", `<entry>\s*=\s*<value>`, s)
				}
				if lhs == "stream" {
					ss = append(ss, strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(rhs, "|"), `[\w\W]*`), `\b`), `\`, ""))
				}
			}
			ss = util.Unique(ss)
			if len(ss) != 1 {
				return errors.Errorf("stream cannot be determined to a single value. values: %v, text: %s", ss, state.Text.Text)
			}
			for i := range pkgs {
				pkgs[i].modularityLabel = fmt.Sprintf("%s:%s", module, ss[0])
			}
		}
	}

	return nil
}

func (e extractor) readRpminfoTest(id string) (oracle.RpminfoTest, error) {
	path := filepath.Join(e.inputDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", id))
	var test oracle.RpminfoTest
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return oracle.RpminfoTest{}, errors.Wrapf(err, "read rpminfo_test json. path: %s", path)
	}
	return test, nil
}

func (e extractor) readTextfilecontent54Test(id string) (oracle.Textfilecontent54Test, error) {
	path := filepath.Join(e.inputDir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", id))
	var test oracle.Textfilecontent54Test
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return oracle.Textfilecontent54Test{}, errors.Wrapf(err, "read textfilecontent54_test json. path: %s", path)
	}
	return test, nil
}

func (e extractor) readRpminfoObj(id string) (oracle.RpminfoObject, error) {
	path := filepath.Join(e.inputDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", id))
	var obj oracle.RpminfoObject
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oracle.RpminfoObject{}, errors.Wrapf(err, "read rpminfo_object json. path: %s", path)
	}
	return obj, nil
}

func (e extractor) readTextfilecontent54Obj(id string) (oracle.Textfilecontent54Object, error) {
	path := filepath.Join(e.inputDir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", id))
	var obj oracle.Textfilecontent54Object
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oracle.Textfilecontent54Object{}, errors.Wrapf(err, "read textfilecontent54_object json. path: %s", path)
	}
	return obj, nil
}

func (e extractor) readRpminfoState(id string) (oracle.RpminfoState, error) {
	path := filepath.Join(e.inputDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", id))
	var state oracle.RpminfoState
	if err := e.r.Read(path, e.inputDir, &state); err != nil {
		return oracle.RpminfoState{}, errors.Wrapf(err, "read rpminfo_state json. path: %s", path)
	}
	return state, nil
}

func (e extractor) readTextfilecontent54OState(id string) (oracle.Textfilecontent54State, error) {
	path := filepath.Join(e.inputDir, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", id))
	var obj oracle.Textfilecontent54State
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oracle.Textfilecontent54State{}, errors.Wrapf(err, "read textfilecontent54_state json. path: %s", path)
	}
	return obj, nil
}
