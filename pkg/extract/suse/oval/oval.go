package oval

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
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

	entries, err := filepath.Glob(filepath.Join(inputDir, "*", "*", "*", "definitions"))
	if err != nil {
		return errors.Wrapf(err, "glob directories \"*/*/*/definitions\" under %s", inputDir)
	}

	for _, entry := range entries {
		elems, err := util.Split(strings.TrimPrefix(entry, inputDir), string(os.PathSeparator), string(os.PathSeparator), string(os.PathSeparator))
		if err != nil {
			return errors.Wrapf(err, "split %s", entry)
		}

		baseDir := filepath.Join(inputDir, elems[0], elems[1], elems[2])
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

			// if err := util.Write(filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			// 	return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)))
			// }

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", inputDir)
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
	case "vulnerability":
		if !strings.HasPrefix(def.ID, "CVE-") {
			return dataTypes.Data{}, errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZZ", def.ID)
		}
		id = def.Metadata.Title
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
		cn, ca, err := e.translateCriterion(oc)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "translace criterion")
		}
		if cn != nil {
			parent.Criterions = append(parent.Criterions, *cn)
		}
		if ca != nil {
			parent.Criterias = append(parent.Criterias, *ca)
		}
	}

	return parent, nil
}

func (e extractor) translateCriterion(parent oval.Criterion) (*criterionTypes.Criterion, *criteriaTypes.Criteria, error) {
	// FIXME items
	// Suppose "AND" criteria, any of sub conditions are not satisfied, drop it.

	var t oval.RpminfoTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "rpminfo_test", parent.TestRef), e.baseDir, &t); err != nil {
		return nil, nil, errors.Wrapf(err, "read rpminfo_test %s", filepath.Join(e.baseDir, "tests", "rpminfo_test", parent.TestRef))
	}

	var o oval.RpminfoObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef), e.baseDir, &o); err != nil {
		return nil, nil, errors.Wrapf(err, "read rpminfo_object %s", filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef))
	}

	var s oval.RpminfoState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef), e.baseDir, &s); err != nil {
		return nil, nil, errors.Wrapf(err, "read rpminfo_state %s", filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef))
	}

	if o.Name == "" {
		return nil, nil, errors.Errorf("unexpected rpminfo_object name. name: %q", o.Name)
	}

	if strings.HasSuffix(parent.Comment, "is not affected") {
		if s.Version.Text == "0" && s.Version.Operation == "equals" {
			return nil, nil, nil
		}
		return nil, nil, errors.Errorf(`unexpected rpminfo_state for "not affected". expected "equals" "0", actual: %q %q`, s.Version.Operation, s.Version.Text)
	}

	switch t.Check {
	case "at least one":
		// exactly one field must be set, others be empty
		if (s.Version.Text != "" && s.Evr.Text != "") || (s.Version.Text != "" && s.Arch.Text != "") || (s.Evr.Text != "" && s.Arch.Text != "") {
			return nil, nil, errors.Errorf("unexpected combination. rpminfo_test check: %s, rpminfo_state version: %q, evr: %q arch: %q", t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}
	case "none satisfy":
		// FIXME: paste raw XML text instead of this plain text
		//
		// Translate to "none exists criterion" OR "version criterion"
		// cf. suse.linux.enterprise.server.15-affected.xml oval:org.opensuse.security:def:201825020
		//            Criteria: AND
		//                Criterion: kernel-default 4.12.14-150.66.1 is installed
		//                  Test   Check:   "at least one"
		//                  Object Name:    "kernel-default"
		//                  Object Version: "1"
		//                  State ID:       "oval:org.opensuse.security:ste:2009169927"
		//                  State Version:  "" (op: "")
		//                  State EVR:      "0:4.12.14-150.66.1" (op: "equals")
		//                  State Arch:     "" (op: "")
		//                Criterion: no kernel-livepatch-4_12_14-150_66-default is greater or equal than 14-2.2 <-- THIS criterion to translate here
		//                  Test   Check:   "none satisfy"
		//                  Object Name:    "kernel-livepatch-4_12_14-150_66-default"
		//                  Object Version: "1"
		//                  State ID:       "oval:org.opensuse.security:ste:2009169922"
		//                  State Version:  "" (op: "")
		//                  State EVR:      "0:14-2.2-0" (op: "greater than or equal")
		//                  State Arch:     "" (op: "")
		//  Translate to:
		//  - criteria OR
		//      - criterion noneexist: kernel-livepatch-4_12_14-150_66-default
		//      - criterion version: kernel-livepatch-4_12_14-150_66-default less than 14-2.2
		if s.Version.Text != "" || s.Arch.Text != "" {
			return nil, nil, errors.Errorf("unexpected combination. rpminfo_test check: %s, rpminfo_state version: %q arch: %q", t.Check, s.Version.Text, s.Arch.Text)
		}
		if s.Evr.Text == "" || s.Evr.Operation != "greater than or equal" {
			return nil, nil, errors.Errorf("unexpected combination. rpminfo_test check: %s, rpminfo_state evr: %q, operation: %q", t.Check, s.Evr.Text, s.Evr.Operation)
		}

		ca := criteriaTypes.Criteria{
			Operator: criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: []criterionTypes.Criterion{
				{
					Type: criterionTypes.CriterionTypeNoneExist,
					NoneExist: &noneexistcriterion.Criterion{
						Type: noneexistcriterion.PackageTypeBinary,
						Binary: &necBinaryTypes.Package{
							Name: o.Name,
						},
					},
				},
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
					},
				},
			},
		}
		return nil, &ca, nil
	case "all":
		if s.Version.Text != "" {
			return nil, nil, errors.Errorf("unexpected combination. rpminfo_test check: %s, rpminfo_state version: %q, evr: %q arch: %q", t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}
	default:
		return nil, nil, errors.Errorf(`unexpected rpminfo_test check. expected: ["at least one", "none satisfy", "all"], actural: %q`, t.Check)
	}

	archs, err := func() ([]string, error) {
		if s.Arch.Text != "" && s.Arch.Operation != "pattern match" {
			return nil, errors.Errorf("unexpected rpminfo_state arch. expected: \"pattern match\", actual: %s", s.Arch.Operation)
		}
		switch s.Arch.Text {
		case "":
			return nil, nil
		default:
			return strings.Split(strings.TrimPrefix(strings.TrimSuffix(s.Arch.Text, ")"), "("), "|"), nil
		}
	}()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "parse rpminfo_state arch")
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
			return nil, nil, errors.Errorf("unexpected rpminfo_state evr operation. expected: [\"less than\", \"greater than\"], actual: %s", s.Evr.Operation)
		}
	}()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "translate rpminfo_state evr")
	}

	c := criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeVersion,
		Version: &versoncriterionTypes.Criterion{
			Vulnerable: s.Evr.Text != "",
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
}
