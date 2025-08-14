package oval

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necbinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	versoncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	cvssV40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval"
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
	inputDir string
	baseDir  string
	osname   string
	version  string
	ovaltype string
	r        *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "suse", "oval"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract SUSE OVAL")

	entries, err := filepath.Glob(filepath.Join(inputDir, "*", "*", "vulnerability", "definitions"))
	if err != nil {
		return errors.Wrapf(err, `glob directories "*/*/*/definitions" under %s`, inputDir)
	}

	for _, entry := range entries {
		rel, err := filepath.Rel(inputDir, entry)
		if err != nil {
			return errors.Wrapf(err, "get relative path %s", entry)
		}

		elems, err := util.Split(strings.TrimPrefix(rel, string(os.PathSeparator)), string(os.PathSeparator), string(os.PathSeparator), string(os.PathSeparator))
		if err != nil {
			return errors.Wrapf(err, "split %s", entry)
		}

		baseDir := filepath.Join(inputDir, elems[0], elems[1], elems[2])
		log.Printf("[INFO] extract OVAL files. dir: %s", filepath.Join(baseDir, "definitions"))

		g, ctx := errgroup.WithContext(context.Background())
		g.SetLimit(options.concurrency)

		reqChan := make(chan string)

		g.Go(func() error {
			defer close(reqChan)

			if err := filepath.WalkDir(filepath.Join(baseDir, "definitions"), func(path string, d fs.DirEntry, err error) error {
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
				return errors.Wrapf(err, "walk %s", filepath.Join(baseDir, "definitions"))
			}

			return nil
		})

		for i := 0; i < options.concurrency; i++ {
			g.Go(func() error {
				for path := range reqChan {
					e := extractor{
						inputDir: inputDir,
						baseDir:  baseDir,
						osname:   elems[0],
						version:  elems[1],
						ovaltype: elems[2],
						r:        utiljson.NewJSONReader(),
					}
					if err := e.extract(path, options.dir); err != nil {
						return errors.Wrapf(err, "extract %s", path)
					}
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return errors.Wrapf(err, "wait for walk")
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.SUSEOVAL,
		Name: func() *string { t := "SUSE OVAL"; return &t }(),
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

func (e extractor) extract(path, outdir string) error {
	var def oval.Definition
	if err := e.r.Read(path, e.inputDir, &def); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	data, err := e.buildData(def)
	if err != nil {
		return errors.Wrapf(err, "build data %s", path)
	}
	if data == nil {
		return nil
	}

	splitted, err := util.Split(string(data.ID), "-", "-")
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: CVE-YYYY-ZZZZ, actual: %s", data.ID)
	}

	if _, err := time.Parse("2006", splitted[1]); err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: CVE-YYYY-ZZZZ, actual: %s", data.ID)
	}

	filename := filepath.Join(outdir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID))
	if _, err := os.Stat(filename); err == nil {
		f, err := os.Open(filename)
		if err != nil {
			return errors.Wrapf(err, "open %s", filename)
		}
		defer f.Close()

		var base dataTypes.Data
		if err := json.NewDecoder(f).Decode(&base); err != nil {
			return errors.Wrapf(err, "decode %s", filename)
		}

		data.Merge(base)
	}

	if err := util.Write(filename, *data, true); err != nil {
		return errors.Wrapf(err, "write %s", filename)
	}

	return nil
}

func (e extractor) buildData(def oval.Definition) (*dataTypes.Data, error) {
	if !strings.HasPrefix(strings.TrimSpace(def.Metadata.Title), "CVE-") {
		return nil, errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZZ", def.Metadata.Title)
	}
	id := strings.TrimSpace(def.Metadata.Title)

	// FIXME: how do we go?
	es := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", e.osname, e.version))

	v, err := buildVulnerability(def)
	if err != nil {
		return nil, errors.Wrapf(err, "build vulnerability %s", def.Metadata.Title)
	}

	c, err := e.walkCriteria(def.Criteria)
	if err != nil {
		return nil, errors.Wrapf(err, "eval criteria")
	}

	return &dataTypes.Data{
		ID: dataTypes.RootID(id),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: v,
				Segments: []segmentTypes.Segment{
					{
						Ecosystem: es,
					},
				},
			},
		},
		Detections: func() []detectionTypes.Detection {
			if c == nil {
				return nil
			}
			return []detectionTypes.Detection{
				{
					Ecosystem: es,
					Conditions: []conditionTypes.Condition{
						{
							Criteria: *c,
						},
					},
				},
			}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.SUSEOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}

func buildVulnerability(def oval.Definition) (vulnerabilityContentTypes.Content, error) {

	refs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference))
	ss := make([]severityTypes.Severity, 0, len(def.Metadata.Advisory.Cve))

	for _, r := range def.Metadata.Reference {
		refs = append(refs, referenceTypes.Reference{
			Source: r.Source,
			URL:    r.RefURL,
		})
	}

	if def.Metadata.Advisory.Severity != "" {
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: def.Metadata.Advisory.From,
			Vendor: &def.Metadata.Advisory.Severity,
		})
	}

	for _, cve := range def.Metadata.Advisory.Cve {
		source := func() string {
			_, rhs, found := strings.Cut(cve.Text, " at ")
			if !found {
				return cve.Text
			}
			if rhs == "SUSE" {
				return "security@suse.de"
			}
			return rhs
		}()

		refs = append(refs, referenceTypes.Reference{
			Source: source,
			URL:    cve.Href,
		})

		if cve.Impact != "" {
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeVendor,
				Source: source,
				Vendor: &cve.Impact,
			})
		}
		if cve.Cvss3 != "" {
			_, rhs, _ := strings.Cut(cve.Cvss3, "/")
			switch {
			case strings.HasPrefix(rhs, "CVSS:3.0"):
				v30, err := cvssV30Types.Parse(rhs)
				if err != nil {
					return vulnerabilityContentTypes.Content{}, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv30,
					Source:  source,
					CVSSv30: v30,
				})
			case strings.HasPrefix(rhs, "CVSS:3.1"):
				v31, err := cvssV31Types.Parse(rhs)
				if err != nil {
					return vulnerabilityContentTypes.Content{}, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv31,
					Source:  source,
					CVSSv31: v31,
				})
			default:
				return vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.Cvss3)
			}
		}
		if cve.Cvss4 != "" {
			_, rhs, _ := strings.Cut(cve.Cvss4, "/")
			switch {
			case strings.HasPrefix(rhs, "CVSS:4.0"):
				v40, err := cvssV40Types.Parse(rhs)
				if err != nil {
					return vulnerabilityContentTypes.Content{}, errors.Wrap(err, "parse cvss4")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv40,
					Source:  source,
					CVSSv40: v40,
				})
			default:
				return vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected CVSSv4 string. expected: %q, actual: %q", "<score>/CVSS:4.0/<vector>", cve.Cvss4)
			}
		}
	}

	for _, b := range def.Metadata.Advisory.Bugzilla {
		refs = append(refs, referenceTypes.Reference{
			Source: func() string {
				if strings.HasPrefix(b.Text, "SUSE bug ") {
					return "security@suse.de"
				}
				return b.Text
			}(),
			URL: b.Href,
		})
	}

	return vulnerabilityContentTypes.Content{
		ID:    vulnerabilityContentTypes.VulnerabilityID(strings.TrimSpace(def.Metadata.Title)),
		Title: def.Metadata.Title,
		Description: func() string {
			if def.Metadata.Description != "" {
				return strings.TrimSpace(def.Metadata.Description)
			}
			return ""
		}(),
		Severity:   ss,
		References: refs,
		Published:  utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
		Modified:   utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Updated.Date),
	}, nil
}

func (e extractor) walkCriteria(oc oval.Criteria) (*criteriaTypes.Criteria, error) {
	if len(oc.Criterias) == 0 && len(oc.Criterions) == 0 {
		return nil, nil
	}

	c := criteriaTypes.Criteria{}

	switch oc.Operator {
	case "OR":
		c.Operator = criteriaTypes.CriteriaOperatorTypeOR
	case "AND":
		c.Operator = criteriaTypes.CriteriaOperatorTypeAND
	default:
		return nil, errors.Errorf(`unexpected oval criteria operator. expected: ["OR", "AND"], actual: %q`, oc.Operator)
	}

	for _, oc := range oc.Criterias {
		child, err := e.walkCriteria(oc)
		if err != nil {
			return nil, errors.Wrapf(err, "walk criteria")
		}

		if c.Operator == criteriaTypes.CriteriaOperatorTypeAND && child == nil {
			return nil, nil
		}
		if child != nil {
			if slices.ContainsFunc(c.Criterias, func(sibling criteriaTypes.Criteria) bool {
				return criteriaTypes.Compare(sibling, *child) == 0
			}) {
				continue
			}
			c.Criterias = append(c.Criterias, *child)
		}
	}

	hasSignatureKeyId := false
	for _, ocn := range oc.Criterions {
		cn, isSignatureKeyId, ca, err := e.translateCriterion(ocn)

		if err != nil {
			return nil, errors.Wrapf(err, "translace criterion")
		}

		if isSignatureKeyId {
			hasSignatureKeyId = true
			continue
		}

		if c.Operator == criteriaTypes.CriteriaOperatorTypeAND && cn == nil && ca == nil {
			return nil, nil
		}
		if cn != nil {
			if slices.ContainsFunc(c.Criterions, func(sibling criterionTypes.Criterion) bool {
				return criterionTypes.Compare(sibling, *cn) == 0
			}) {
				continue
			}
			c.Criterions = append(c.Criterions, *cn)
		}
		if ca != nil {
			if slices.ContainsFunc(c.Criterias, func(sibling criteriaTypes.Criteria) bool {
				return criteriaTypes.Compare(sibling, *ca) == 0
			}) {
				continue
			}
			c.Criterias = append(c.Criterias, *ca)
		}
	}

	if len(c.Criterias) == 0 && len(c.Criterions) == 0 {
		if hasSignatureKeyId {
			return nil, errors.Errorf("unexpected empty criteria. criteria: %v", oc)
		}
		return nil, nil
	}

	return &c, nil
}

// translateCriterion translates an oval.Criterion to a criterionTypes.Criterion.
// If the criterion is SignatureKeyid,, the second return value is true and vice versa.
// If the first return value is nil, it means that the criterion is never satisfired.
func (e extractor) translateCriterion(oc oval.Criterion) (*criterionTypes.Criterion, bool, *criteriaTypes.Criteria, error) {
	var t oval.RpminfoTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", oc.TestRef)), e.inputDir, &t); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err := e.translateUnameCriterion(oc)
			if err != nil {
				return nil, false, nil, errors.Wrapf(err, "translate uname criterion %s", oc.TestRef)
			}
			return nil, false, nil, nil
		}

		return nil, false, nil, errors.Wrapf(err, "read rpminfo_test %s", filepath.Join(e.baseDir, "tests", "rpminfo_test", oc.TestRef))
	}

	var o oval.RpminfoObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.inputDir, &o); err != nil {
		return nil, false, nil, errors.Wrapf(err, "read rpminfo_object %s", filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef))
	}

	var s oval.RpminfoState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.inputDir, &s); err != nil {
		return nil, false, nil, errors.Wrapf(err, "read rpminfo_state %s", filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef))
	}

	if o.Name == "" {
		return nil, false, nil, errors.Errorf("unexpected rpminfo_object name. name: %q", o.Name)
	}

	if s.SignatureKeyid.Text != "" {
		if s.Version.Text != "" || s.Evr.Text != "" || s.Arch.Text != "" {
			return nil, false, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q, evr: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}
		return nil, true, nil, nil
	}

	if strings.HasSuffix(oc.Comment, "is not affected") {
		// sanity check
		if s.Version.Text != "0" || s.Version.Operation != "equals" {
			return nil, false, nil, errors.Errorf(`unexpected rpminfo_state for "not affected". test: %s, expected "equals" "0", actual: %q %q`, oc.TestRef, s.Version.Operation, s.Version.Text)
		}

		return nil, false, nil, nil
	}

	switch t.Check {
	case "at least one":
		if (s.Version.Text == "" && s.Evr.Text == "") || (s.Version.Text != "" && s.Evr.Text != "") {
			return nil, false, nil, errors.Errorf("only version or evr should be set. test: %s, check: %q, version: %q, evr: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text)
		}

		if s.Version.Text != "" {
			if s.Arch.Text != "" {
				return nil, false, nil, errors.Errorf(`unexpected arch. test: %s, check: %q, expected: "", actual: %q`, oc.TestRef, t.Check, s.Arch.Text)
			}

			if s.Version.Operation != "equals" {
				return nil, false, nil, errors.Errorf(`unexpected operation. test: %s, expected: "equals", actual: %q`, oc.TestRef, s.Version.Operation)
			}

			switch e.osname {
			case "suse.linux.enterprise.server":
				if o.Name == "sled-release" {
					return nil, false, nil, nil
				}
			case "suse.linux.enterprise.desktop":
				if o.Name == "sles-release" {
					return nil, false, nil, nil
				}
			default:
			}
			return &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &versoncriterionTypes.Criterion{
					Vulnerable: false,
					Package: criterionpackageTypes.Package{
						Type: criterionpackageTypes.PackageTypeBinary,
						Binary: &binaryTypes.Package{
							Name: o.Name,
						},
					},
					Affected: &affectedTypes.Affected{
						Type: affectedrangeTypes.RangeTypeRPMVersionOnly,
						Range: []affectedrangeTypes.Range{
							{
								Equal: s.Version.Text,
							},
						},
					},
				},
			}, false, nil, nil
		}

		// case that EVR is set
		vulnerable, fixstatus, ranges, err := func() (bool, *fixstatusTypes.FixStatus, []affectedrangeTypes.Range, error) {
			switch s.Evr.Operation {
			case "less than":
				return true, &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassFixed,
					}, []affectedrangeTypes.Range{{
						LessThan: s.Evr.Text,
					}}, nil

			case "greater than or equal":
				// suse.linux.enterprise.server.11-affected.xml oval:org.opensuse.security:def:20042771 has
				// a criterion of "greater than or equal" exists in "SUSE Linux Enterprise Server 11-SECURITY is installed" test.
				// Also, opensuse tumbleweed has such criterias in "openSUSE Tumbleweed is installed" tests.
				if !strings.HasSuffix(o.Name, "-release") {
					return false, nil, nil, errors.Errorf("unexpected rpminfo_state evr operation. test; %s, expected: [\"less than\"], actual: %q", oc.TestRef, s.Evr.Operation)
				}

				return false, nil, []affectedrangeTypes.Range{{
					GreaterEqual: s.Evr.Text,
				}}, nil
			case "greater than":
				if s.Evr.Text != "0:0-0" {
					return false, nil, nil, errors.Errorf("unexpected rpminfo_state evr. test: %s, expected: \"0:0-0\", oc.TestRef, actual: %q", oc.TestRef, s.Evr.Text)
				}

				return true, &fixstatusTypes.FixStatus{
					Class: fixstatusTypes.ClassUnfixed,
				}, nil, nil
			case "equals":
				// Sibling of kernel-livepatch pattern
				if !strings.HasPrefix(o.Name, "kernel-") {
					return false, nil, nil, errors.Errorf(`unexpected rpminfo_object name. test: %s, expected: "kernel-*", actual: %q`, oc.TestRef, o.Name)
				}

				return true, &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassUnknown,
					}, []affectedrangeTypes.Range{{
						Equal: s.Evr.Text,
					}}, nil
			default:
				return false, nil, nil, errors.Errorf(`unexpected evr operation. test: %s, expected: ["less than", "greater than or equal", "greater than", "equals"], actual: %q`, oc.TestRef, s.Evr.Operation)
			}
		}()
		if err != nil {
			return nil, false, nil, errors.Wrap(err, "translate rpminfo_state EVR.")
		}

		archs, err := architectures(s.Arch.Text)
		if err != nil {
			return nil, false, nil, errors.Wrapf(err, "architectures")
		}

		return &criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &versoncriterionTypes.Criterion{
				Vulnerable: vulnerable,
				FixStatus:  fixstatus,
				Package: criterionpackageTypes.Package{
					Type: criterionpackageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{
						Name:          o.Name,
						Architectures: archs,
					},
				},
				Affected: func() *affectedTypes.Affected {
					if len(ranges) == 0 {
						return nil
					}
					return &affectedTypes.Affected{
						Type:  affectedrangeTypes.RangeTypeRPM,
						Range: ranges,
					}
				}(),
			},
		}, false, nil, nil

	case "all":
		// EVR case only for "all"
		if s.Version.Text != "" {
			return nil, false, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q", oc.TestRef, t.Check, s.Version.Text)
		}

		if s.Arch.Text != "" && s.Arch.Operation != "pattern match" {
			return nil, false, nil, errors.Errorf(`unexpected rpminfo_state arch operation. test: %s, expected: "pattern match", actual: %q`, oc.TestRef, s.Arch.Operation)
		}

		affected, fixstatus, err := func() (*affectedTypes.Affected, *fixstatusTypes.FixStatus, error) {
			if s.Evr.Text == "" {
				return nil, nil, nil
			}

			switch s.Evr.Operation {
			case "less than":
				return &affectedTypes.Affected{
						Type: affectedrangeTypes.RangeTypeRPM,
						Range: []affectedrangeTypes.Range{
							{LessThan: s.Evr.Text},
						},
					},
					&fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassFixed,
					}, nil
			case "greater than":
				if s.Evr.Text != "0:0-0" {
					return nil, nil, errors.Errorf(`unexpected evr. test: %s, expected: "0:0-0", actual: %q`, oc.TestRef, s.Evr.Text)
				}
				return nil, &fixstatusTypes.FixStatus{
					Class: fixstatusTypes.ClassUnfixed,
				}, nil
			default:
				return nil, nil, errors.Errorf(`unexpected rpminfo_state evr operation. test: %s, expected: ["less than", "greater than"], actual: %q`, oc.TestRef, s.Evr.Operation)
			}
		}()
		if err != nil {
			return nil, false, nil, errors.Wrapf(err, "translate rpminfo_state evr. test: %s", oc.TestRef)
		}

		archs, err := architectures(s.Arch.Text)
		if err != nil {
			return nil, false, nil, errors.Wrapf(err, "architectures")
		}

		c := criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &versoncriterionTypes.Criterion{
				Vulnerable: true,
				FixStatus:  fixstatus,
				Package: criterionpackageTypes.Package{
					Type: criterionpackageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{
						Name:          o.Name,
						Architectures: archs,
					},
				},
				Affected: affected,
			},
		}

		return &c, false, nil, nil

	case "none satisfy":
		// Translation of "none satisfy" rpminfo_test.
		// For "none satisfy" rpminfo_test, it will be evalucated false if the corresponding rpminfo_object does not exist.
		// cf. https://oval.mitre.org/language/version5.10.1/ovaldefinition/documentation/oval-definitions-schema.html#TestType
		//     > An OVAL Test evaluates to true if both the check_existence and check attributes are satisfied during evaluation.
		//     > If the result of evaluating the check_existence attribute is true then the check attribute is evaluated
		// Example from suse.linux.enterprise.server.15-affected.xml:
		//     <definition id="oval:org.opensuse.security:def:201825020" version="1" class="vulnerability">
		//     [snip]
		//       <criteria operator="AND">
		//         <criterion test_ref="oval:org.opensuse.security:tst:2009276218" comment="SUSE Linux Enterprise Server for SAP Applications 15 is installed"/>
		//         <criteria operator="OR">
		//           <criteria operator="OR">
		//             <criteria operator="AND">
		//               <criterion test_ref="oval:org.opensuse.security:tst:2009712009" comment="kernel-default 4.12.14-150.66.1 is installed"/>
		//               <criterion test_ref="oval:org.opensuse.security:tst:2009712010" comment="no kernel-livepatch-4_12_14-150_66-default is greater or equal than 14-2.2"/>
		//             </criteria>
		//
		//    <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:org.opensuse.security:tst:2009712010" version="1"
		//        comment="kernel-livepatch-4_12_14-150_66-default is &gt;=14-2.2" check="none satisfy">  // <--- THIS PART
		//      <object object_ref="oval:org.opensuse.security:obj:2009050495"/>
		//      <state state_ref="oval:org.opensuse.security:ste:2009169922"/>
		//    </rpminfo_test>
		//
		//    <rpminfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:org.opensuse.security:obj:2009050495" version="1">
		//      <name>kernel-livepatch-4_12_14-150_66-default</name>
		//    </rpminfo_object>
		//
		//    <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:org.opensuse.security:ste:2009169922" version="1">
		//      <evr datatype="evr_string" operation="greater than or equal">0:14-2.2-0</evr>
		//    </rpminfo_state>

		// Limit to kernel-livepatch-* and kgraft-patch-* packages. If not, it's time to investigate the raw data to re-think how they should be translated.
		if !strings.HasPrefix(o.Name, "kernel-livepatch-") && !strings.HasPrefix(o.Name, "kgraft-patch-") {
			return nil, false, nil, errors.Errorf(`unexpected rpminfo_object. test: %s, rpminfo_test check: %q, expected: ["kernel-livepatch-*", "kgraft-patch-*"],rpminfo_object name: %q`, oc.TestRef, t.Check, o.Name)
		}
		if s.Version.Text != "" || s.Arch.Text != "" {
			return nil, false, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Arch.Text)
		}
		if s.Evr.Text == "" || s.Evr.Operation != "greater than or equal" {
			return nil, false, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state evr: %q, operation: %q", oc.TestRef, t.Check, s.Evr.Text, s.Evr.Operation)
		}

		return nil, false,
			&criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &versoncriterionTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: o.Name,
								},
							},
							Affected: &affectedTypes.Affected{
								Type: affectedrangeTypes.RangeTypeRPM,
								Range: []affectedrangeTypes.Range{
									{LessThan: s.Evr.Text},
								},
							},
							FixStatus: &fixstatusTypes.FixStatus{
								Class: fixstatusTypes.ClassFixed,
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeNoneExist,
						NoneExist: &necTypes.Criterion{
							Type: necTypes.PackageTypeBinary,
							Binary: &necbinaryTypes.Package{
								Name: o.Name,
							},
						},
					},
				},
			}, nil

	default:
		return nil, false, nil, errors.Errorf(`unexpected rpminfo_test check. test: %s, expected: ["at least one", "none satisfy", "all"], actural: %q`, oc.TestRef, t.Check)
	}
}

func (e extractor) translateUnameCriterion(oc oval.Criterion) error {
	var t oval.UnameTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "uname_test", fmt.Sprintf("%s.json", oc.TestRef)), e.inputDir, &t); err != nil {
		return errors.Wrapf(err, "read uname_test %s", filepath.Join(e.baseDir, "tests", "uname_test", oc.TestRef))
	}

	var o oval.UnameObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "uname_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.inputDir, &o); err != nil {
		return errors.Wrapf(err, "read uname_object %s", filepath.Join(e.baseDir, "objects", "uname_object", t.Object.ObjectRef))
	}

	var s oval.UnameState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "uname_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.inputDir, &s); err != nil {
		return errors.Wrapf(err, "read uname_state %s", filepath.Join(e.baseDir, "states", "uname_state", t.State.StateRef))
	}

	// only file existence check, just return.
	return nil
}

func architectures(arch string) ([]string, error) {
	if arch == "" {
		return nil, nil
	}

	archs := strings.Split(strings.TrimPrefix(strings.TrimSuffix(arch, ")"), "("), "|")
	for _, a := range archs {
		if !slices.Contains([]string{"aarch64", "aarch64_ilp32", "i586", "i686", "ia64", "ppc", "ppc64", "ppc64le", "s390", "s390x", "x86_64", "noarch"}, a) {
			return nil, errors.Errorf(`unexpected arch. expected: ["aarch64", "aarch64_ilp32", "i586", "i686", "ia64", "ppc", "ppc64", "ppc64le", "s390", "s390x", "x86_64", "noarch"], actual: %s`, arch)
		}
	}
	return archs, nil
}
