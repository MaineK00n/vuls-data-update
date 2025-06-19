package oval

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	versoncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval" // SUSE OVAL用のfetchパッケージ
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
	baseDir  string
	osname   string
	version  string
	ovaltype string
	r        *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "oval"),
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

		elems, err := util.Split(strings.TrimPrefix(strings.TrimPrefix(entry, inputDir), string(os.PathSeparator)), string(os.PathSeparator), string(os.PathSeparator), string(os.PathSeparator))
		if err != nil {
			return errors.Wrapf(err, "split %s", entry)
		}

		baseDir := filepath.Join(inputDir, elems[0], elems[1], elems[2])
		log.Printf("[INFO] extract OVAL files. dir: %s", filepath.Join(baseDir, "definitions"))

		if err := filepath.WalkDir(filepath.Join(baseDir, "definitions"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			e := extractor{
				inputDir: inputDir,
				baseDir:  baseDir,
				osname:   elems[0],
				version:  elems[1],
				ovaltype: elems[2],
				r:        utiljson.NewJSONReader(),
			}
			var def oval.Definition
			if err := e.r.Read(path, e.baseDir, &def); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}

			_, err = e.extract(def)
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
			}

			// SUSE用のID形式に対応した分割処理
			// 例: SUSE-SU-2023-1234-1 のような形式を想定
			// splitted, err := util.Split(string(data.ID), "-", "-")
			// if err != nil {
			// 	return errors.Wrapf(err, "unexpected ID format for SUSE. actual: %q", data.ID)
			// }

			// if len(splitted) < 3 {
			// 	return errors.Errorf("unexpected SUSE ID format. expected: SUSE-<TYPE>-<YEAR>-<ID>, actual: %q", data.ID)
			// }

			// // SUSE-SU-2023-1234-1 -> year = 2023
			// year := splitted[2]
			// if _, err := time.Parse("2006", year); err != nil {
			// 	return errors.Wrapf(err, "unexpected year format in ID. actual: %q", data.ID)
			// }

			// FIXME: merge if a file exists

			// if err := util.Write(filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			// 	return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)))
			// }

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", baseDir)
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

func (e extractor) extract(def oval.Definition) (dataTypes.Data, error) {
	id := ""
	switch def.Class {
	case "patch":
		for _, r := range def.Metadata.Reference {
			if r.Source == "SUSE-SU" {
				if id != "" {
					return dataTypes.Data{}, errors.Errorf("multiple SUSE-SU references found. definition: %s", def.ID)
				}
				id = r.RefID
			}
		}
		if id == "" {
			return dataTypes.Data{}, errors.Errorf("no SUSE-SU reference found. definition: %s", def.ID)
		}
	case "vulnerability":
		if !strings.HasPrefix(strings.TrimSpace(def.Metadata.Title), "CVE-") {
			return dataTypes.Data{}, errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZZ", def.Metadata.Title)
		}
		id = strings.TrimSpace(def.Metadata.Title)
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected class %s in definition %s (%s/%s)", def.Class, def.ID, e.osname, e.version)
	}

	_, err := e.walkCriteria(def.Criteria)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "eval criteria")
	}

	// TODO: SUSE固有のデータ抽出ロジックを実装
	// - パッケージ情報の収集
	// - 脆弱性情報の抽出
	// - セキュリティアドバイザリ情報の構築

	// 基本的なデータ構造を返す（実装は要調整）
	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		// Advisories: // TODO: アドバイザリ情報を構築
		// Vulnerabilities: // TODO: 脆弱性情報を構築
		// Detections: // TODO: 検出条件を構築
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.SUSEOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}

type pkg struct {
	name    string
	fixedAt string
}

func (e extractor) walkCriteria(ovalParent oval.Criteria) (criteriaTypes.Criteria, error) {
	op, err := func() (criteriaTypes.CriteriaOperatorType, error) {
		switch ovalParent.Operator {
		case "OR":
			return criteriaTypes.CriteriaOperatorTypeOR, nil
		case "AND":
			return criteriaTypes.CriteriaOperatorTypeAND, nil
		default:
			return criteriaTypes.CriteriaOperatorType(0), errors.Errorf(`unexpected oval criteria operator. expected: ["OR", "AND"], actual: %s`, ovalParent.Operator)
		}
	}()
	if err != nil {
		return criteriaTypes.Criteria{}, errors.Wrapf(err, "parse criteria operator %s", ovalParent.Operator)
	}

	parent := criteriaTypes.Criteria{
		Operator: op,
	}

	for _, oc := range ovalParent.Criterias {
		c, err := e.walkCriteria(oc)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "walk criteria")
		}
		parent.Criterias = append(parent.Criterias, c)
	}
	for _, oc := range ovalParent.Criterions {
		c, err := e.translateCriterion(oc)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "translace criterion")
		}
		if c != nil {
			parent.Criterions = append(parent.Criterions, *c)
		}
	}

	return parent, nil
}

func (e extractor) translateCriterion(oc oval.Criterion) (*criterionTypes.Criterion, error) {
	// FIXME items
	// Suppose "AND" criteria, any of sub conditions are not satisfied, drop it.

	var t oval.RpminfoTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", oc.TestRef)), e.baseDir, &t); err != nil {
		return nil, errors.Wrapf(err, "read rpminfo_test %s", filepath.Join(e.baseDir, "tests", "rpminfo_test", oc.TestRef))
	}

	var o oval.RpminfoObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.baseDir, &o); err != nil {
		return nil, errors.Wrapf(err, "read rpminfo_object %s", filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef))
	}

	var s oval.RpminfoState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.baseDir, &s); err != nil {
		return nil, errors.Wrapf(err, "read rpminfo_state %s", filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef))
	}

	if o.Name == "" {
		return nil, errors.Errorf("unexpected rpminfo_object name. name: %q", o.Name)
	}

	if strings.HasSuffix(oc.Comment, "is not affected") {
		if s.Version.Text == "0" && s.Version.Operation == "equals" {
			return nil, nil
		}
		return nil, errors.Errorf(`unexpected rpminfo_state for "not affected". test: %s, expected "equals" "0", actual: %q %q`, oc.TestRef, s.Version.Operation, s.Version.Text)
	}

	switch t.Check {
	case "at least one":
		if (s.Version.Text == "" && s.Evr.Text == "") || (s.Version.Text != "" && s.Evr.Text != "") {
			return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state version: %q, evr: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}

		if s.Version.Text != "" {
			if s.Arch.Text != "" {
				return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state version: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Arch.Text)
			}

			r, err := func() (affectedrangeTypes.Range, error) {
				switch s.Version.Operation {
				case "equals":
					return affectedrangeTypes.Range{
						Equal: s.Version.Text,
					}, nil
				default:
					return affectedrangeTypes.Range{}, errors.Errorf("unexpected rpminfo_state version operation. test: %s, expected: \"equals\", actual: %q", oc.TestRef, s.Version.Operation)
				}
			}()
			if err != nil {
				return nil, errors.Wrapf(err, "parse rpminfo_state version. test: %s, version: %s", oc.TestRef, s.Version.Text)
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
						Type:  affectedrangeTypes.RangeTypeRPMVersionOnly,
						Range: []affectedrangeTypes.Range{r},
					},
				},
			}, nil
		}

		vulnerable, ranges, err := func() (bool, []affectedrangeTypes.Range, error) {
			switch s.Evr.Operation {
			case "less than":
				return true, []affectedrangeTypes.Range{{
					LessThan: s.Version.Text,
				}}, nil
			case "greater than or equal":
				if e.osname == "opensuse" && e.version == "tumbleweed" {
					// FIXME: validate package name, too
					return false, []affectedrangeTypes.Range{{
						GreaterEqual: s.Version.Text,
					}}, nil
				}

				return false, nil, errors.Errorf("unexpected rpminfo_state evr operation. test; %s, expected: [\"less than\"], actual: %q", oc.TestRef, s.Evr.Operation)
			case "greater than":
				if s.Evr.Text != "0:0-0" {
					return false, nil, errors.Errorf("unexpected rpminfo_state evr. test: %s, expected: \"0:0-0\", oc.TestRef, actual: %q", s.Evr.Text)
				}

				return true, nil, nil
			case "equals":
				// Sibling of kernel-livepatch pattern
				if o.Name != "kernel-default" {
					return false, nil, errors.Errorf("unexpected rpminfo_state evr. test: %s, expected: \"kernel-default\", actual: %q", oc.TestRef, o.Name)
				}
				return false, nil, nil
			default:
				return false, nil, errors.Errorf("unexpected rpminfo_state evr operation. test: %s, expected: [\"less than\"], actual: %q", oc.TestRef, s.Evr.Operation)
			}
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "parse rpminfo_state version. test: %s, version: %s", oc.TestRef, s.Version.Text)
		}

		return &criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &versoncriterionTypes.Criterion{
				Vulnerable: vulnerable,
				FixStatus: func() *fixstatusTypes.FixStatus {
					if !vulnerable {
						return nil
					}
					if len(ranges) == 0 {
						return &fixstatusTypes.FixStatus{
							Class: fixstatusTypes.ClassUnfixed,
						}
					}
					return &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassFixed,
					}
				}(),
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
		}, nil

	case "all":
		if s.SignatureKeyid.Text != "" {
			if s.Version.Text != "" || s.Evr.Text != "" || s.Arch.Text != "" {
				return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state version: %q, evr: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
			}
			return nil, nil
		}
		if s.Version.Text != "" {
			return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state version: %q", oc.TestRef, t.Check, s.Version.Text)
		}
		if s.Arch.Text != "" && s.Arch.Operation != "pattern match" {
			return nil, errors.Errorf(`unexpected rpminfo_state arch operation. test: %s, expected: "pattern match", actual: %q`, oc.TestRef, s.Arch.Operation)
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
				return &affectedTypes.Affected{
						Type: affectedrangeTypes.RangeTypeRPM,
						Range: []affectedrangeTypes.Range{
							{GreaterThan: s.Evr.Text},
						},
					},
					&fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassUnfixed,
					}, nil
			default:
				return nil, nil, errors.Errorf(`unexpected rpminfo_state evr operation. test: %s, expected: ["less than", "greater than"], actual: %q`, oc.TestRef, s.Evr.Operation)
			}
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "translate rpminfo_state evr. test: %s", oc.TestRef)
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

		return &c, nil

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

		// Limit to kernel-livepatch-* packages. If not, it's time to investigate the raw data to re-think how they should be translated.
		if !strings.HasPrefix(o.Name, "kernel-livepatch-") {
			return nil, errors.Errorf("unexpected rpminfo_object. test: %s, rpminfo_test check: %s, rpminfo_object name: %q", oc.TestRef, t.Check, o.Name)
		}
		if s.Version.Text != "" || s.Arch.Text != "" {
			return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state version: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Arch.Text)
		}
		if s.Evr.Text == "" || s.Evr.Operation != "greater than or equal" {
			return nil, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %s, rpminfo_state evr: %q, operation: %q", oc.TestRef, t.Check, s.Evr.Text, s.Evr.Operation)
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
					Type: affectedrangeTypes.RangeTypeRPM,
					Range: []affectedrangeTypes.Range{
						{LessThan: s.Evr.Text},
					},
				},
			},
		}, nil

	default:
		return nil, errors.Errorf(`unexpected rpminfo_test check. test: %s, expected: ["at least one", "none satisfy", "all"], actural: %q`, oc.TestRef, t.Check)
	}
}
