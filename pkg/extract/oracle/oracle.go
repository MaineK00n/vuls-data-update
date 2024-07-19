package oracle

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
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

// tos means _T_ests, _O_bjects and _S_tates. Information for evaluating OVAL criteria.
type tos struct {
	rpminfoTests   map[string]oracle.Test
	textfileTests  map[string]oracle.Test
	rpminfoObjs    map[string]oracle.RpminfoObject
	textfileObjs   map[string]oracle.Textfilecontent54Object
	rpminfoStates  map[string]oracle.RpminfoState
	textfileStates map[string]oracle.Textfilecontent54State
}

func Extract(inputPath string, opts ...Option) error {
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

	rpminfoTests, textfileTests, err := readTests(filepath.Join(inputPath, "tests"))
	if err != nil {
		return err
	}
	rpminfoObjs, textfileObjs, err := readObjects(filepath.Join(inputPath, "objects"))
	if err != nil {
		return err
	}
	rpminfoStates, textfileStates, err := readStates(filepath.Join(inputPath, "states"))
	if err != nil {
		return err
	}

	tos := tos{
		rpminfoTests:   rpminfoTests,
		textfileTests:  textfileTests,
		rpminfoObjs:    rpminfoObjs,
		textfileObjs:   textfileObjs,
		rpminfoStates:  rpminfoStates,
		textfileStates: textfileStates,
	}
	if err := filepath.WalkDir(filepath.Join(inputPath, "definitions"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var ovalDef oracle.Definition
		if err := json.NewDecoder(f).Decode(&ovalDef); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		data, err := extract(ovalDef, tos)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", inputPath)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Oracle,
		Name: func() *string { t := "Oracle Linux OVAL"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(inputPath)
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

// Structs to collect packages by major version and gather architectures
type packages map[majorType]perMajorPackages
type majorType string
type perMajorPackages map[packageKey]archtectures
type packageKey struct {
	name         string
	fixedVersion string
}
type archtectures []string

func extract(ovalDef oracle.Definition, tos tos) (dataTypes.Data, error) {
	data := dataTypes.Data{
		ID: ovalDef.ID,
		Advisories: []advisoryTypes.Advisory{{
			ID:          ovalDef.ID,
			Title:       ovalDef.Metadata.Title,
			Description: ovalDef.Metadata.Description,
			Severity: []severityTypes.Severity{{
				Type:   severityTypes.SeverityTypeVendor,
				Source: "linux.oracle.com/security",
				Vendor: &ovalDef.Metadata.Advisory.Severity}},
			Published: utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, ovalDef.Metadata.Advisory.Issued.Date),
		}},
		DataSource: sourceTypes.Oracle,
	}

	refURLs := map[string]struct{}{}             // URL -> struct{}
	vulnURLs := map[string]map[string]struct{}{} // vuln ID -> URL -> struct{}

	for _, r := range ovalDef.Metadata.Reference {
		refURLs[r.RefURL] = struct{}{}
		if r.Source == "CVE" {
			if vulnURLs[r.RefID] == nil {
				vulnURLs[r.RefID] = map[string]struct{}{}
			}
			vulnURLs[r.RefID][r.RefURL] = struct{}{}
		}
	}
	for _, c := range ovalDef.Metadata.Advisory.Cve {
		vulnURLs[c.Text][c.Href] = struct{}{}
	}

	data.Vulnerabilities = func() []vulnerabilityTypes.Vulnerability {
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(vulnURLs))
		for vulnID, urls := range vulnURLs {
			vs = append(vs, vulnerabilityTypes.Vulnerability{
				ID: vulnID,
				References: func() []referenceTypes.Reference {
					refs := make([]referenceTypes.Reference, 0, len(urls))
					for url := range urls {
						refs = append(refs, referenceTypes.Reference{
							Source: "linux.oracle.com/security",
							URL:    url,
						})
					}
					return refs
				}(),
			})
		}
		return vs
	}()

	data.Advisories[0].References = func() []referenceTypes.Reference {
		refs := make([]referenceTypes.Reference, 0, len(refURLs))
		for url := range refURLs {
			refs = append(refs, referenceTypes.Reference{
				Source: "linux.oracle.com/security",
				URL:    url,
			})
		}
		return refs
	}()

	allPkgs, err := collectPackages(ovalDef.Criteria, tos)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collectPackages, definition: %s", ovalDef.ID)
	}

	data.Detection = func() []detectionTypes.Detection {
		ds := make([]detectionTypes.Detection, 0, len(allPkgs))
		for major, pkgs := range allPkgs {
			ds = append(ds, detectionTypes.Detection{
				Ecosystem: detectionTypes.Ecosystem(fmt.Sprintf("%s:%s", detectionTypes.EcosystemTypeOracle, major)),
				Criteria: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: func() []criterionTypes.Criterion {
						criterions := make([]criterionTypes.Criterion, 0, len(pkgs))
						for pkg, archs := range pkgs {
							criterions = append(criterions, criterionTypes.Criterion{
								Vulnerable: true,
								Package: packageTypes.Package{
									Name:          pkg.name,
									Architectures: archs,
								},
								Affected: &affectedTypes.Affected{
									Type:  rangeTypes.RangeTypeRPM,
									Range: []rangeTypes.Range{{LessThan: pkg.fixedVersion}},
									Fixed: []string{pkg.fixedVersion},
								},
							})
						}
						return criterions
					}(),
				},
			})
		}
		return ds
	}()

	return data, nil
}

type ovalPackage struct {
	major           string
	ovalName        string
	fixedVersion    string
	modularityLabel string
	arch            string
}

func collectPackages(criteria oracle.Criteria, tos tos) (packages, error) {
	pkgs, err := evalCriteria(criteria, tos)
	if err != nil {
		return packages{}, errors.Wrapf(err, "applyCriteria")
	}

	allPkgs := packages{}
	for _, p := range pkgs {
		pkgs, ok := allPkgs[majorType(p.major)]
		if !ok {
			pkgs = perMajorPackages{}
			allPkgs[majorType(p.major)] = pkgs
		}
		key := packageKey{
			name: func() string {
				switch p.modularityLabel {
				case "":
					return p.ovalName
				default:
					return fmt.Sprintf("%s::%s", p.modularityLabel, p.ovalName)
				}
			}(),
			fixedVersion: p.fixedVersion,
		}
		pkgs[key] = append(pkgs[key], p.arch)
	}
	return allPkgs, nil
}

func evalCriteria(criteria oracle.Criteria, tos tos) ([]ovalPackage, error) {
	// Exclude patterns that do not exists in oracle oval data and don't implement them, YAGNI.
	// With these constraints, we can ignore Criteria.Operator (AND or OR) to extract package information.
	switch {
	case criteria.Operator == "OR" && len(criteria.Criterions) > 0:
		return []ovalPackage{}, errors.Errorf("criteriaons under OR criteria MUST not exist")
	case criteria.Operator == "OR" && len(criteria.Criterias) == 0:
		return []ovalPackage{}, errors.Errorf("criterias under OR criteria MUST exist")
	case criteria.Operator == "AND" && len(criteria.Criterias) > 1:
		return []ovalPackage{}, errors.Errorf("criterias under AND-criteria MUST be < 2")
	}

	var pkgs []ovalPackage

	for _, ca := range criteria.Criterias {
		ps, err := evalCriteria(ca, tos)
		if err != nil {
			return []ovalPackage{}, err
		}
		pkgs = append(pkgs, ps...)
	}

	if err := evalCriterions(&pkgs, tos, criteria.Criterions); err != nil {
		return []ovalPackage{}, err
	}
	return pkgs, nil
}

func evalCriterions(pkgs *[]ovalPackage, tos tos, criterions []oracle.Criterion) error {
	if len(criterions) == 0 {
		return nil
	}

	// The case for parent criterion is AND and without child criterions case. Add base (ANY) one
	if len(*pkgs) == 0 {
		*pkgs = append(*pkgs, ovalPackage{})
	}

	for _, c := range criterions {
		test, ok := tos.rpminfoTests[c.TestRef]
		if ok {
			obj, ok := tos.rpminfoObjs[test.Object.ObjectRef]
			if !ok {
				return errors.Errorf("no objectref: %s", test.Object.ObjectRef)
			}
			state, ok := tos.rpminfoStates[test.State.StateRef]
			if !ok {
				return errors.Errorf("no stateref: %s", test.State.StateRef)
			}

			switch obj.Name {
			case "oraclelinux-release":
				switch {
				case state.Version != nil:
					for i := range *pkgs {
						(*pkgs)[i].major = strings.TrimPrefix(state.Version.Text, "^")
					}
				case state.Arch != nil:
					for i := range *pkgs {
						(*pkgs)[i].arch = state.Arch.Text
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
					for i := range *pkgs {
						(*pkgs)[i].ovalName = obj.Name
						(*pkgs)[i].fixedVersion = state.Evr.Text
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
			test, ok := tos.textfileTests[c.TestRef]
			if !ok {
				return errors.Errorf("no testref: %s", c.TestRef)
			}
			obj, ok := tos.textfileObjs[test.Object.ObjectRef]
			if !ok {
				return errors.Errorf("no objectref: %s", test.Object.ObjectRef)
			}
			state, ok := tos.textfileStates[test.State.StateRef]
			if !ok {
				return errors.Errorf("no stateref: %s", test.State.StateRef)
			}
			if !strings.HasPrefix(obj.Filepath.Text, "/etc/dnf/modules.d/") {
				continue
			}

			// <ind-def:pattern operation="pattern match">\[container\-tools\][\w\W]*</ind-def:pattern>
			module := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(obj.Pattern.Text, `\[`), `\][\w\W]*`), `\`, "")
			// <ind-def:text operation="pattern match">\nstream\s*=\s*ol8\b[\w\W]*\nstate\s*=\s*(enabled|1|true)|\nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*ol8\b</ind-def:text>
			streamWithBackSlashes, _, _ := strings.Cut(strings.TrimPrefix(state.Text.Text, `\nstream\s*=\s*`), `\b[\w\W]`)
			// There may be "." in stream and should be unescaped
			stream := strings.ReplaceAll(streamWithBackSlashes, `\`, "")
			for i := range *pkgs {
				(*pkgs)[i].modularityLabel = fmt.Sprintf("%s:%s", module, stream)
			}
		}
	}

	return nil
}

func readTests(testsRoot string) (map[string]oracle.Test, map[string]oracle.Test, error) {
	rpminfoTests := map[string]oracle.Test{}
	textfileTests := map[string]oracle.Test{}

	if err := filepath.WalkDir(filepath.Join(testsRoot), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched oracle.Test
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}
		rel, err := filepath.Rel(testsRoot, path)
		if err != nil {
			return err
		}
		switch filepath.Dir(rel) {
		case "rpminfo_test":
			rpminfoTests[fetched.ID] = fetched
		case "textfilecontent54_test":
			textfileTests[fetched.ID] = fetched
		}
		return nil
	}); err != nil {
		return map[string]oracle.Test{}, map[string]oracle.Test{}, errors.Wrapf(err, "walk %s", testsRoot)
	}

	return rpminfoTests, textfileTests, nil
}

func readObjects(objectsRoot string) (map[string]oracle.RpminfoObject, map[string]oracle.Textfilecontent54Object, error) {
	rpminfoObjs := map[string]oracle.RpminfoObject{}
	textinfoObjs := map[string]oracle.Textfilecontent54Object{}

	if err := filepath.WalkDir(filepath.Join(objectsRoot), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		rel, err := filepath.Rel(objectsRoot, path)
		if err != nil {
			return err
		}
		switch filepath.Dir(rel) {
		case "rpminfo_object":
			var fetched oracle.RpminfoObject
			if err := json.NewDecoder(f).Decode(&fetched); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}
			rpminfoObjs[fetched.ID] = fetched
		case "textfilecontent54_object":
			var fetched oracle.Textfilecontent54Object
			if err := json.NewDecoder(f).Decode(&fetched); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}
			textinfoObjs[fetched.ID] = fetched
		}

		return nil
	}); err != nil {
		return map[string]oracle.RpminfoObject{}, map[string]oracle.Textfilecontent54Object{}, errors.Wrapf(err, "walk %s", objectsRoot)
	}

	return rpminfoObjs, textinfoObjs, nil
}

func readStates(statesRoot string) (map[string]oracle.RpminfoState, map[string]oracle.Textfilecontent54State, error) {
	rpminfoStates := map[string]oracle.RpminfoState{}
	textfileStates := map[string]oracle.Textfilecontent54State{}

	if err := filepath.WalkDir(statesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		rel, err := filepath.Rel(statesRoot, path)
		if err != nil {
			return err
		}
		switch filepath.Dir(rel) {
		case "rpminfo_state":
			var fetched oracle.RpminfoState
			if err := json.NewDecoder(f).Decode(&fetched); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}

			rpminfoStates[fetched.ID] = fetched
		case "textfilecontent54_state":
			var fetched oracle.Textfilecontent54State
			if err := json.NewDecoder(f).Decode(&fetched); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}
			textfileStates[fetched.ID] = fetched
		}
		return nil
	}); err != nil {
		return map[string]oracle.RpminfoState{}, map[string]oracle.Textfilecontent54State{}, errors.Wrapf(err, "walk %s", statesRoot)
	}

	return rpminfoStates, textfileStates, nil
}
