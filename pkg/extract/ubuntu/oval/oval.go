package oval

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

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
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
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
	inputDir  string
	path      string
	release   string
	service   string
	outputDir string
	r         *utiljson.JSONReader
}

// Mutexes for output file overwrite protection, key is output file path and value is a *sync.Mutex to protect it.
// Values are not sync.Mutex but reference to them because sysm.Mutex must not be copied.
var locks = sync.Map{}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "", ""),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Ubuntu OVAL")

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(options.concurrency)
	reqChan := make(chan extractor)

	g.Go(func() error {
		defer close(reqChan)
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

			select {
			case reqChan <- extractor{
				inputDir:  inputDir,
				path:      path,
				release:   ss[0],
				service:   ss[2],
				outputDir: options.dir,
				r:         utiljson.NewJSONReader(),
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", inputDir)
		}
		return nil
	})

	for i := 0; i < options.concurrency; i++ {
		g.Go(func() error {
			for e := range reqChan {
				if err := e.extract(); err != nil {
					return errors.Wrapf(err, "extract %s", e.path)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return errors.Wrapf(err, "wait for walk")
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

func (e extractor) extract() error {
	var def oval.CVEDefinition
	if err := e.r.Read(e.path, e.inputDir, &def); err != nil {
		return errors.Wrapf(err, "read json %s", e.path)
	}

	if def.ID == "oval:com.ubuntu.jammy:def:100" {
		return nil
	}

	data, err := e.toData(def)
	if err != nil {
		return errors.Wrapf(err, "extract %s", e.path)
	}

	tokens := strings.Split(data.ID, "-")
	if len(tokens) < 2 {
		return errors.Errorf("unexpected ID format. expected: CVE-YYYY-ZZZZZ, actual: %s, path: %s", data.ID, e.path)
	}
	datapath := filepath.Join(e.outputDir, "data", tokens[1], fmt.Sprintf("%s.json", data.ID))

	switch v, _ := locks.LoadOrStore(datapath, &sync.Mutex{}); lock := v.(type) {
	case *sync.Mutex:
		lock.Lock()
		defer lock.Unlock()
	default:
		return errors.Errorf("unexpected type. expected: *sync.Mutex, actual: %+v", v)
	}

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

		// baseUSNs := make([]string, 0)
		// for _, a := range base.Advisories {
		// 	if strings.HasPrefix(a.Content.ID, "USN-") {
		// 		baseUSNs = append(baseUSNs, a.Content.ID)
		// 	}
		// }
		// data.Advisories = slices.DeleteFunc(data.Advisories, func(a advisoryTypes.Advisory) bool {
		// 	return slices.Contains(baseUSNs, a.Content.ID)
		// })
		data.Merge(base)
	}

	if err := util.Write(datapath, data, true); err != nil {
		return errors.Wrapf(err, "write %s", datapath)
	}

	return nil
}

var reUbuntuVersion = regexp.MustCompile(`Ubuntu.* (\d\d\.\d\d) `)

func (e extractor) toData(def oval.CVEDefinition) (dataTypes.Data, error) {
	id, _, ok := strings.Cut(def.Metadata.Title, " on Ubuntu ")
	if !ok {
		return dataTypes.Data{}, errors.Errorf("unexpected title format. expected: %q, actual: %q", "<CVE ID> on Ubuntu ...", def.Metadata.Title)
	}

	matched := reUbuntuVersion.FindStringSubmatch(def.Metadata.Affected.Platform)
	if len(matched) != 2 {
		return dataTypes.Data{}, errors.Errorf("ubuntu version not found. platform: %s", def.Metadata.Affected.Platform)
	}
	es := ecosystemTypes.Ecosystem{Family: fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeUbuntu, matched[1]), Branch: e.service}

	ds, err := e.collectPackages(def.Criteria, es)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collectPackages, definition: %s", def.ID)
	}

	cvssSeverities, err := parseCvss(def.Metadata.Advisory.Cve.CvssVector, def.Metadata.Advisory.Cve.Href)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "parse CVSS")
	}

	advisories, err := e.usnAdvisories(def.Metadata.Advisory.Cve.Usns, es)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collect USN. CVE definition: %s", def.ID)
	}

	return dataTypes.Data{
		ID:         id,
		Advisories: advisories,
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: vulnerabilityContentTypes.Content{
					ID:          id,
					Title:       strings.TrimSpace(def.Metadata.Title),
					Description: strings.TrimSpace(def.Metadata.Description),
					Severity:    cvssSeverities,
					References: []referenceTypes.Reference{{
						Source: "security-metadata.canonical.com/oval/",
						URL:    def.Metadata.Reference.RefURL,
					}},
					Published: utiltime.Parse([]string{"2006-01-02 15:04:05 UTC"}, def.Metadata.Advisory.PublicDate),
				},
				Ecosystems: []ecosystemTypes.Ecosystem{es},
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
	patchStatus  criterionTypes.PatchStatus
}

func (e extractor) usnAdvisories(usns string, es ecosystemTypes.Ecosystem) ([]advisoryTypes.Advisory, error) {
	if usns == "" {
		return nil, nil
	}

	ids := strings.Split(usns, ",")
	as := make([]advisoryTypes.Advisory, 0, len(ids))
	for _, u := range ids {
		ss := strings.Split(u, "-")
		if len(ss) != 2 {
			return nil, errors.Errorf("unexpected USN format. expected: XXXX-Y, actural: %s", u)
		}

		var def oval.USNDefinition
		path := filepath.Join(e.inputDir, e.release, "usn", "definitions", fmt.Sprintf("oval:com.ubuntu.%s:def:%s%s000000.json", e.release, ss[0], ss[1]))
		if err := e.r.Read(path, e.inputDir, &def); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, errors.Wrapf(err, "read json. path: %s", path)
		}

		as = append(as, advisoryTypes.Advisory{
			Content: advisoryContentTypes.Content{
				ID:          fmt.Sprintf("USN-%s-%s", ss[0], ss[1]),
				Title:       def.Metadata.Title,
				Description: def.Metadata.Description,
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "security-metadata.canonical.com/oval/",
					Vendor: &def.Metadata.Advisory.Severity,
				}},
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference))
					for _, r := range def.Metadata.Reference {
						rs = append(rs, referenceTypes.Reference{
							Source: "security-metadata.canonical.com/oval/",
							URL:    r.RefURL,
						})
					}
					return rs
				}(),
			},
			Ecosystems: []ecosystemTypes.Ecosystem{es},
		})
	}
	return as, nil
}

func (e extractor) collectPackages(criteria oval.Criteria, es ecosystemTypes.Ecosystem) ([]detectionTypes.Detection, error) {
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
		Ecosystem: es,
		Criteria: criteriaTypes.Criteria{
			Operator: criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: func() []criterionTypes.Criterion {
				cns := make([]criterionTypes.Criterion, 0, len(pkgs))
				for _, p := range pkgs {
					switch p.fixedVersion {
					case "":
						cns = append(cns, criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackage.Package{
								Name: p.name,
							},
							PatchStatus: p.patchStatus,
						})
					default:
						cns = append(cns, criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackage.Package{
								Name: p.name,
							},
							Affected: &affected.Affected{
								Type:  affectedrange.RangeTypeDPKG,
								Range: []affectedrange.Range{{LessThan: p.fixedVersion}},
								Fixed: []string{p.fixedVersion},
							},
							PatchStatus: p.patchStatus,
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
		if p == nil {
			continue
		}
		pkgs = append(pkgs, *p)
	}

	return pkgs, nil
}

var rePkgComment = regexp.MustCompile(`The '(.*)' package binar.+`)

func (e extractor) evalCriterion(cn oval.Criterion) (*ovalPackage, error) {
	test, err := e.readTest("textfilecontent54_test", cn.TestRef)
	if err != nil {
		return nil, errors.Wrapf(err, "read textfilecontent54_test. ref: %s", cn.TestRef)
	}

	obj, err := e.readObject(test.Object.ObjectRef)
	if err != nil {
		return nil, errors.Wrapf(err, "read textfilecontent54_object. ref: %s", test.Object.ObjectRef)
	}

	matched := rePkgComment.FindAllStringSubmatch(obj.Comment, 1)
	if len(matched[0]) != 2 {
		return nil, errors.Errorf("object comment does not have pakcage name. comment: %s", obj.Comment)
	}

	p := ovalPackage{name: matched[0][1]}

	switch {
	case strings.Contains(cn.Comment, "is related to the CVE in some way and has been fixed"): // status: not vulnerable(= not affected)
		return nil, nil
	case strings.Contains(cn.Comment, "is affected and may need fixing"): // status: needs-triage
		p.patchStatus = criterionTypes.PatchStatusNeedsTriage

	case strings.Contains(cn.Comment, "is affected and needs fixing"): // status: needed
		p.patchStatus = criterionTypes.PatchStatusNeeded
	case strings.Contains(cn.Comment, "is affected, but a decision has been made to defer addressing it"): // status: deferred
		p.patchStatus = criterionTypes.PatchStatusDeferred
	case strings.Contains(cn.Comment, "is affected. An update containing the fix has been completed and is pending publication"): // status: pending
		p.patchStatus = criterionTypes.PatchStatusPending
	case strings.Contains(cn.Comment, "while related to the CVE in some way, a decision has been made to ignore this issue"): // status: ignored
		p.patchStatus = criterionTypes.PatchStatusIgnored

	case strings.Contains(cn.Comment, "was vulnerable but has been fixed"), // status: released
		strings.Contains(cn.Comment, "was vulnerable and has been fixed"): // status: released, only this comment: "firefox package in $RELEASE_NAME was vulnerable and has been fixed, but no release version available for it."
		p.patchStatus = criterionTypes.PatchStatusReleased

		state, err := e.readState(test.State.StateRef)
		if err != nil {
			return nil, errors.Wrapf(err, "read textfilecontent54_state. ref: %s", test.State.StateRef)
		}
		if state.Subexpression.Datatype == "debian_evr_string" && state.Subexpression.Operation == "less than" {
			p.fixedVersion = strings.TrimSpace(state.Subexpression.Text)
		}
		p.fixedVersion = strings.TrimSpace(state.Subexpression.Text)
	default:
		return nil, errors.Errorf("patch status not found. comment: %s", cn.Comment)
	}

	return &p, nil
}

func (e extractor) readTest(testType, id string) (oval.Textfilecontent54Test, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "tests", testType, fmt.Sprintf("%s.json", id))
	var test oval.Textfilecontent54Test
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return oval.Textfilecontent54Test{}, errors.Wrapf(err, "read %s json. path: %s", testType, path)
	}
	return test, nil
}

func (e extractor) readObject(id string) (oval.Textfilecontent54Object, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", id))
	var obj oval.Textfilecontent54Object
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oval.Textfilecontent54Object{}, errors.Wrapf(err, "read textfilecontent54_object json. path: %s", path)
	}
	return obj, nil
}

func (e extractor) readState(id string) (oval.Textfilecontent54State, error) {
	path := filepath.Join(e.inputDir, e.release, "cve", e.service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", id))
	var obj oval.Textfilecontent54State
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return oval.Textfilecontent54State{}, errors.Wrapf(err, "read textfilecontent54_state json. path: %s", path)
	}
	return obj, nil
}

func parseCvss(vector, href string) ([]severityTypes.Severity, error) {
	before, _, found := strings.Cut(vector, "/")
	if !found {
		return nil, nil
	}

	switch before {
	case "CVSS:2.0":
		v2, err := v2.Parse(vector)
		if err != nil {
			return nil, errors.Wrapf(err, "cvss v2 parse. vector: %s", vector)
		}
		return []severityTypes.Severity{{
			Type:   severityTypes.SeverityTypeCVSSv2,
			Source: href,
			CVSSv2: v2,
		}}, nil
	case "CVSS:3.0":
		v30, err := v30.Parse(vector)
		if err != nil {
			return nil, errors.Wrapf(err, "cvss v3.0 parse. vector: %s", vector)
		}
		return []severityTypes.Severity{{
			Type:    severityTypes.SeverityTypeCVSSv30,
			Source:  href,
			CVSSv30: v30,
		}}, nil
	case "CVSS:3.1":
		v31, err := v31.Parse(vector)
		if err != nil {
			return nil, errors.Wrapf(err, "cvss v3.1 parse. vector: %s", vector)
		}
		return []severityTypes.Severity{{
			Type:    severityTypes.SeverityTypeCVSSv31,
			Source:  href,
			CVSSv31: v31,
		}}, nil
	case "CVSS:4.0":
		v40, err := v40.Parse(vector)
		if err != nil {
			return nil, errors.Wrapf(err, "cvss v4.0 parse. vector: %s", vector)
		}
		return []severityTypes.Severity{{
			Type:    severityTypes.SeverityTypeCVSSv31,
			Source:  href,
			CVSSv40: v40,
		}}, nil
	default:
		return nil, errors.Errorf("invalid CVSS vector: %s", vector)
	}
}
