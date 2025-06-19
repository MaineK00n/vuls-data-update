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
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necbinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	unamecriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/unamecriterion"
	versoncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval" // SUSE OVAL用のfetchパッケージ
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

	c, err := e.walkCriteria(def.Criteria)
	if err != nil {
		return nil, errors.Wrapf(err, "eval criteria")
	}

	// TODO: SUSE固有のデータ抽出ロジックを実装
	// - パッケージ情報の収集
	// - 脆弱性情報の抽出
	// - セキュリティアドバイザリ情報の構築

	// 基本的なデータ構造を返す（実装は要調整）
	return &dataTypes.Data{
		ID: dataTypes.RootID(id),
		// Advisories: // TODO: アドバイザリ情報を構築
		// Vulnerabilities: // TODO: 脆弱性情報を構築
		Detections: func() []detection.Detection {
			if c == nil {
				return nil
			}
			return []detection.Detection{
				{
					Conditions: []condition.Condition{
						{
							Criteria: *c,
							// FIXME: what is suitable?
							Tag: segment.DetectionTag(fmt.Sprintf("%s-%s-%s", e.osname, e.version, e.ovaltype)),
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
			c.Criterias = append(c.Criterias, *child)
		}
	}

	for _, oc := range oc.Criterions {
		cn, ca, err := e.translateCriterion(oc)
		if err != nil {
			return nil, errors.Wrapf(err, "translace criterion")
		}

		if c.Operator == criteriaTypes.CriteriaOperatorTypeAND && cn == nil && ca == nil {
			return nil, nil
		}
		if cn != nil {
			c.Criterions = append(c.Criterions, *cn)
		}
		if ca != nil {
			c.Criterias = append(c.Criterias, *ca)
		}
	}

	if len(c.Criterias) == 0 && len(c.Criterions) == 0 {
		return nil, nil
	}

	return &c, nil
}

func (e extractor) translateCriterion(oc oval.Criterion) (*criterionTypes.Criterion, *criteriaTypes.Criteria, error) {
	var t oval.RpminfoTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", oc.TestRef)), e.inputDir, &t); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			uc, err := e.translateUnameCriterion(oc)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "translate uname criterion %s", oc.TestRef)
			}
			return uc, nil, nil
		}

		return nil, nil, errors.Wrapf(err, "read rpminfo_test %s", filepath.Join(e.baseDir, "tests", "rpminfo_test", oc.TestRef))
	}

	var o oval.RpminfoObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.inputDir, &o); err != nil {
		return nil, nil, errors.Wrapf(err, "read rpminfo_object %s", filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef))
	}

	var s oval.RpminfoState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.inputDir, &s); err != nil {
		return nil, nil, errors.Wrapf(err, "read rpminfo_state %s", filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef))
	}

	if o.Name == "" {
		return nil, nil, errors.Errorf("unexpected rpminfo_object name. name: %q", o.Name)
	}

	if s.SignatureKeyid.Text != "" {
		if s.Version.Text != "" || s.Evr.Text != "" || s.Arch.Text != "" {
			return nil, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q, evr: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}
		return nil, nil, nil
	}

	if strings.HasSuffix(oc.Comment, "is not affected") {
		// sanity check
		if s.Version.Text != "0" || s.Version.Operation != "equals" {
			return nil, nil, errors.Errorf(`unexpected rpminfo_state for "not affected". test: %s, expected "equals" "0", actual: %q %q`, oc.TestRef, s.Version.Operation, s.Version.Text)
		}

		return nil, nil, nil
	}

	switch t.Check {
	case "at least one":
		if (s.Version.Text == "" && s.Evr.Text == "") || (s.Version.Text != "" && s.Evr.Text != "") {
			return nil, nil, errors.Errorf("only version or evr should be set. test: %s, check: %q, version: %q, evr: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text)
		}

		if s.Version.Text != "" {
			if s.Arch.Text != "" {
				return nil, nil, errors.Errorf(`unexpected arch. test: %s, check: %q, expected: "", actual: %q`, oc.TestRef, t.Check, s.Arch.Text)
			}

			if s.Version.Operation != "equals" {
				return nil, nil, errors.Errorf(`unexpected operation. test: %s, expected: "equals", actual: %q`, oc.TestRef, s.Version.Operation)
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
			}, nil, nil
		}

		// case that EVR is set
		vulnerable, fixstatus, ranges, err := func() (bool, *fixstatusTypes.FixStatus, []affectedrangeTypes.Range, error) {
			switch s.Evr.Operation {
			case "less than":
				return true, &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassFixed,
					}, []affectedrangeTypes.Range{{
						LessThan: s.Version.Text,
					}}, nil

			case "greater than or equal":
				// suse.linux.enterprise.server.11-affected.xml oval:org.opensuse.security:def:20042771 has
				// A criterion of "greater than or equal" exists in "SUSE Linux Enterprise Server 11-SECURITY is installed" test.
				// Also, opensuse tumbleweed has such criterias in "openSUSE Tumbleweed is installed" tests.
				if !strings.HasSuffix(o.Name, "-release") {
					return false, nil, nil, errors.Errorf("unexpected rpminfo_state evr operation. test; %s, expected: [\"less than\"], actual: %q", oc.TestRef, s.Evr.Operation)
				}

				return false, nil, []affectedrangeTypes.Range{{
					GreaterEqual: s.Version.Text,
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

				// FIXME: use fixstatus of unknown
				return true, nil, []affectedrangeTypes.Range{{
					Equal: s.Evr.Text,
				}}, nil
			default:
				return false, nil, nil, errors.Errorf(`unexpected evr operation. test: %s, expected: ["less than", "greater than or equal", "greater than", "equals"], actual: %q`, oc.TestRef, s.Evr.Operation)
			}
		}()
		if err != nil {
			return nil, nil, errors.Wrap(err, "translate rpminfo_state version.")
		}

		return &criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &versoncriterionTypes.Criterion{
				Vulnerable: vulnerable,
				FixStatus:  fixstatus,
				Package: criterionpackageTypes.Package{
					Type: criterionpackageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{
						Name: o.Name,
						Architectures: func() []string {
							switch s.Arch.Text {
							case "":
								return nil
							default:
								return strings.Split(strings.TrimPrefix(strings.TrimSuffix(s.Arch.Text, ")"), "("), "|")
							}
						}(),
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
		}, nil, nil

	case "all":
		if s.Version.Text != "" {
			return nil, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q", oc.TestRef, t.Check, s.Version.Text)
		}

		if s.Arch.Text != "" && s.Arch.Operation != "pattern match" {
			return nil, nil, errors.Errorf(`unexpected rpminfo_state arch operation. test: %s, expected: "pattern match", actual: %q`, oc.TestRef, s.Arch.Operation)
		}

		archs := func() []string {
			switch s.Arch.Text {
			case "":
				return nil
			default:
				return strings.Split(strings.TrimPrefix(strings.TrimSuffix(s.Arch.Text, ")"), "("), "|")
			}
		}()

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
			return nil, nil, errors.Wrapf(err, "translate rpminfo_state evr. test: %s", oc.TestRef)
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

		return &c, nil, nil

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
			return nil, nil, errors.Errorf(`unexpected rpminfo_object. test: %s, rpminfo_test check: %q, expected: ["kernel-livepatch-*", "kgraft-patch-*"],rpminfo_object name: %q`, oc.TestRef, t.Check, o.Name)
		}
		if s.Version.Text != "" || s.Arch.Text != "" {
			return nil, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Arch.Text)
		}
		if s.Evr.Text == "" || s.Evr.Operation != "greater than or equal" {
			return nil, nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state evr: %q, operation: %q", oc.TestRef, t.Check, s.Evr.Text, s.Evr.Operation)
		}

		return nil,
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
		return nil, nil, errors.Errorf(`unexpected rpminfo_test check. test: %s, expected: ["at least one", "none satisfy", "all"], actural: %q`, oc.TestRef, t.Check)
	}
}

func (e extractor) translateUnameCriterion(oc oval.Criterion) (*criterionTypes.Criterion, error) {
	var t oval.UnameTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "uname_test", fmt.Sprintf("%s.json", oc.TestRef)), e.inputDir, &t); err != nil {
		return nil, errors.Wrapf(err, "read uname_test %s", filepath.Join(e.baseDir, "tests", "uname_test", oc.TestRef))
	}

	var o oval.UnameObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "uname_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.inputDir, &o); err != nil {
		return nil, errors.Wrapf(err, "read uname_object %s", filepath.Join(e.baseDir, "objects", "uname_object", t.Object.ObjectRef))
	}

	var s oval.UnameState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "uname_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.inputDir, &s); err != nil {
		return nil, errors.Wrapf(err, "read uname_state %s", filepath.Join(e.baseDir, "states", "uname_state", t.State.StateRef))
	}

	if s.OSRelease.Operation != "pattern match" {
		return nil, errors.Errorf(`unexpected uname_state os_release operation. test: %s, expected: "pattern match", actual: %q`, oc.TestRef, s.OSRelease.Operation)
	}
	if _, err := regexp.Compile(s.OSRelease.Text); err != nil {
		return nil, errors.Wrapf(err, "compile uname_state os_release regexp. test: %s, text: %q", oc.TestRef, s.OSRelease.Text)
	}

	return &criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeUname,
		Uname: &unamecriterionTypes.Criterion{
			Release: &s.OSRelease.Text,
		},
	}, nil
}
