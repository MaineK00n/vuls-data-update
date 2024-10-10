package oval

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	affectedrange "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	criterionpackage "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/oval"
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
	release  string
	service  string
	r        *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "", ""),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Ubuntu OVAL")
	if err := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(inputDir, path)
		if err != nil {
			return errors.Wrapf(err, "relative filepath. prefix: %q, path: %q", inputDir, path)
		}

		ss := strings.Split(rel, string(filepath.Separator))
		switch len(ss) {
		case 2:
			if ss[1] != "cve" {
				return filepath.SkipDir
			}
			return nil
		case 4:
			if ss[3] != "definitions" {
				return filepath.SkipDir
			}
			return nil
		default:
			if len(ss) < 3 || d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
		}

		e := extractor{
			inputDir: inputDir,
			release:  ss[0],
			service:  ss[2],
			r:        utiljson.NewJSONReader(),
		}
		var def oval.CVEDefinition
		if err := e.r.Read(path, e.inputDir, &def); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		if def.ID == "oval:com.ubuntu.jammy:def:100" {
			return nil
		}

		data, err := e.extract(def)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		tokens := strings.Split(data.ID, "-")
		if len(tokens) < 2 {
			return errors.Errorf("unexpected ID format. expected: CVE-YYYY-ZZZZZ, actual: %s", data.ID)
		}
		datapath := filepath.Join(options.dir, "data", tokens[1], fmt.Sprintf("%s.json", data.ID))
		if _, err := os.Stat(datapath); err == nil {
			f, err := os.Open(datapath)
			if err != nil {
				return errors.Wrapf(err, "open %s", datapath)
			}
			defer f.Close()

			var base dataTypes.Data
			if err := json.NewDecoder(f).Decode(&base); err != nil {
				return errors.Wrapf(err, "decode %s", datapath)
			}

			data.Merge(base)
		}

		if err := util.Write(datapath, data, true); err != nil {
			return errors.Wrapf(err, "write %s", datapath)
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", inputDir)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.UbuntuOVAL,
		Name: func() *string { t := "Ubuntu OVAL"; return &t }(),
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

var reUbuntuVersion = regexp.MustCompile(`Ubuntu.* (\d\d\.\d\d) `)

func (e extractor) extract(def oval.CVEDefinition) (dataTypes.Data, error) {
	id, _, ok := strings.Cut(def.Metadata.Title, " on Ubuntu ")
	if !ok {
		return dataTypes.Data{}, errors.Errorf("unexpected title format. expected: %q, actual: %q", "<CVE ID> on Ubuntu ...", def.Metadata.Title)
	}

	matched := reUbuntuVersion.FindStringSubmatch(def.Metadata.Affected.Platform)
	if len(matched) != 2 {
		return dataTypes.Data{}, errors.Errorf("ubuntu version not found. platform: %s", def.Metadata.Affected.Platform)
	}

	ubuntuVer := matched[1]
	es := []ecosystemTypes.Ecosystem{
		ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeUbuntu, ubuntuVer)),
	}

	ds, err := e.collectPackages(def.Criteria, ubuntuVer)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collectPackages, definition: %s", def.ID)
	}

	// var cvssSeverity severityTypes.Severity
	// switch strings.Split(def.Metadata.Advisory.Cve.CvssVector, "/")[0] {
	// case "CVSS:3.1":
	// 	v31, err := v31Types.Parse(def.Metadata.Advisory.Cve.CvssVector)
	// 	if err != nil {
	// 		return dataTypes.Data{}, errors.Wrapf(err, "cvss v3.1 parse. vector: %s", def.Metadata.Advisory.Cve.CvssVector)
	// 	}
	// 	cvssSeverity = severityTypes.Severity{
	// 		Type:    severityTypes.SeverityTypeCVSSv31,
	// 		Source:  def.Metadata.Advisory.Cve.Href,
	// 		CVSSv31: v31,
	// 	}
	// default:
	// 	return dataTypes.Data{}, errors.Wrapf(err, "invalid CVSS vector: %s", def.Metadata.Advisory.Cve.CvssVector)
	// }
	return dataTypes.Data{
		ID: id,
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          id,
				Title:       strings.TrimSpace(def.Metadata.Title),
				Description: strings.TrimSpace(def.Metadata.Description),
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "security-metadata.canonical.com/oval/",
					Vendor: &def.Metadata.Advisory.Severity}},
				References: []referenceTypes.Reference{
					{
						Source: "security-metadata.canonical.com/oval/",
						URL:    def.Metadata.Reference.RefURL,
					},
				},
				Published: utiltime.Parse([]string{"2006-01-02 15:04:05 UTC"}, def.Metadata.Advisory.PublicDate),
			},
			Ecosystems: es,
		}},
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: vulnerabilityContentTypes.Content{
					ID: id,
					// Severity: []severityTypes.Severity{cvssSeverity},
					References: []referenceTypes.Reference{{
						Source: "security-metadata.canonical.com/oval/",
						URL:    def.Metadata.Reference.RefURL,
					}},
				},
				Ecosystems: es,
			},
		},
		Detection: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.UbuntuOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}

type ovalPackage struct {
	name         string
	fixedVersion string
}

func (e extractor) collectPackages(criteria oval.Criteria, ubuntuVer string) ([]detectionTypes.Detection, error) {
	if len(criteria.Criterions) > 0 {
		return nil, errors.Errorf("criterions under root criteria must be empty.")
	}
	if criteria.Operator != "" && criteria.Operator != criteriaTypes.CriteriaOperatorTypeOR.String() {
		return nil, errors.Errorf("operator under root criteria must be OR.")
	}
	if len(criteria.Criterias) != 1 {
		return nil, errors.Errorf("criterias under root criteria must have length 1.")
	}

	pkgs, err := e.evalCriteria(criteria.Criterias[0])
	if err != nil {
		return nil, errors.Wrapf(err, "eval inner criteria")
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeUbuntu, ubuntuVer)),
		Criteria: criteriaTypes.Criteria{
			Operator: criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: func() []criterionTypes.Criterion {
				cns := make([]criterionTypes.Criterion, 0, len(pkgs))
				for _, p := range pkgs {
					switch p.fixedVersion {
					case "":
						cns = append(cns, criterionTypes.Criterion{
							Vulnerable: true,
							Package:    criterionpackage.Package{Name: p.name},
							Affected: &affected.Affected{
								Type:  affectedrange.RangeTypeDPKG,
								Range: []affectedrange.Range{{LessThan: p.fixedVersion}},
							},
						})
					default:
						cns = append(cns, criterionTypes.Criterion{
							Vulnerable: true,
							Package:    criterionpackage.Package{Name: p.name},
							Affected: &affected.Affected{
								Type:  affectedrange.RangeTypeDPKG,
								Range: []affectedrange.Range{{LessThan: p.fixedVersion}},
							},
						})
					}
				}
				return cns
			}(),
		}}}, nil
}

func (e extractor) evalCriteria(criteria oval.Criteria) ([]ovalPackage, error) {
	if len(criteria.Criterias) > 0 {
		return nil, errors.Errorf("criterias under inner criteria must be empty.")
	}
	if criteria.Operator != criteriaTypes.CriteriaOperatorTypeOR.String() {
		return nil, errors.Errorf("operator under inner criteria must be OR.")
	}

	pkgs := make([]ovalPackage, 0, len(criteria.Criterions))

	for _, cn := range criteria.Criterions {
		p, err := e.evalCriterion(cn)
		if err != nil {
			return nil, errors.Wrapf(err, "eval criterion")
		}
		pkgs = append(pkgs, p)
	}

	return pkgs, nil
}

var rePkgComment = regexp.MustCompile(`The '(.*)' package binar.+`)

func (e extractor) evalCriterion(cn oval.Criterion) (ovalPackage, error) {
	test, err := e.readTest("textfilecontent54_test", cn.TestRef)
	if err != nil {
		return ovalPackage{}, errors.Wrapf(err, "read textfilecontent54_test. ref: %s", cn.TestRef)
	}

	obj, err := e.readTextfilecontent54Obj(test.Object.ObjectRef)
	if err != nil {
		return ovalPackage{}, errors.Wrapf(err, "read textfilecontent54_object. ref: %s", test.Object.ObjectRef)
	}

	matched := rePkgComment.FindAllStringSubmatch(obj.Comment, 1)
	if len(matched[0]) != 2 {
		return ovalPackage{}, errors.Errorf("object comment does not have pakcage name. comment: %s", obj.Comment)
	}

	p := ovalPackage{name: matched[0][1]}

	if strings.Contains(cn.Comment, "is related to the CVE in some way and has been fixed") || // status: not vulnerable(= not affected)
		strings.Contains(cn.Comment, "is affected and may need fixing") { // status: needs-triage
		return p, nil
	}

	if strings.Contains(cn.Comment, "is affected and needs fixing") || // status: needed
		strings.Contains(cn.Comment, "is affected, but a decision has been made to defer addressing it") || // status: deferred
		strings.Contains(cn.Comment, "is affected. An update containing the fix has been completed and is pending publication") || // status: pending
		strings.Contains(cn.Comment, "while related to the CVE in some way, a decision has been made to ignore this issue") { // status: ignored
		return p, nil
	}

	if strings.Contains(cn.Comment, "was vulnerable but has been fixed") || // status: released
		strings.Contains(cn.Comment, "was vulnerable and has been fixed") { // status: released, only this comment: "firefox package in $RELEASE_NAME was vulnerable and has been fixed, but no release version available for it."

		state, err := e.readTextfilecontent54OState(test.State.StateRef)
		if err != nil {
			return ovalPackage{}, errors.Wrapf(err, "read textfilecontent54_state. ref: %s", test.State.StateRef)
		}
		if state.Subexpression.Datatype == "debian_evr_string" && state.Subexpression.Operation == "less than" {
			p.fixedVersion = strings.TrimSpace(state.Subexpression.Text)
		}

		p.fixedVersion = state.Subexpression.Text
		return p, nil
	}

	return ovalPackage{}, errors.Errorf("patch status not found. comment: %s", cn.Comment)
}

func (e extractor) readTest(testType, id string) (oval.Textfilecontent54Test, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "tests", testType, fmt.Sprintf("%s.json", id))
	var test oval.Textfilecontent54Test
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return oval.Textfilecontent54Test{}, errors.Wrapf(err, "read %s json. path: %s", testType, path)
	}
	return test, nil
}

func (e extractor) readTextfilecontent54Obj(id string) (oval.Textfilecontent54Object, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", id))
	var obj oval.Textfilecontent54Object
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oval.Textfilecontent54Object{}, errors.Wrapf(err, "read textfilecontent54_object json. path: %s", path)
	}
	return obj, nil
}

func (e extractor) readTextfilecontent54OState(id string) (oval.Textfilecontent54State, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", id))
	var obj oval.Textfilecontent54State
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oval.Textfilecontent54State{}, errors.Wrapf(err, "read textfilecontent54_state json. path: %s", path)
	}
	return obj, nil
}
