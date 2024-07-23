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
		return errors.Wrap(err, "read tests")
	}
	rpminfoObjs, textfileObjs, err := readObjects(filepath.Join(inputPath, "objects"))
	if err != nil {
		return errors.Wrap(err, "read objects")
	}
	rpminfoStates, textfileStates, err := readStates(filepath.Join(inputPath, "states"))
	if err != nil {
		return errors.Wrap(err, "read states")
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

		var def oracle.Definition
		if err := json.NewDecoder(f).Decode(&def); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		data, err := extract(def, tos)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		ss := strings.Split(data.ID, "-")
		if len(ss) < 3 || ss[0] != "ELSA" {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "ELSA-<year>-<ID>", data.ID)
		}
		year := ss[1]

		if err := util.Write(filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)))
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

func extract(def oracle.Definition, tos tos) (dataTypes.Data, error) {
	id, _, ok := strings.Cut(strings.TrimSpace(def.Metadata.Title), ":")
	if !ok {
		return dataTypes.Data{}, errors.Errorf("unexpected title format. expected: %q, actual: %q", "<Advisory ID>: ...", def.Metadata.Title)
	}

	ds, err := collectPackages(def.Criteria, tos)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "collectPackages, definition: %s", def.ID)
	}

	return dataTypes.Data{
		ID: id,
		Advisories: []advisoryTypes.Advisory{{
			ID:          id,
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
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(def.Metadata.Advisory.Cve))
			for _, cve := range def.Metadata.Advisory.Cve {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					ID: cve.Text,
					References: []referenceTypes.Reference{{
						Source: "linux.oracle.com/security",
						URL:    cve.Href,
					}},
				})
			}
			return vs
		}(),
		Detection:  ds,
		DataSource: sourceTypes.Oracle,
	}, nil
}

type ovalPackage struct {
	major           string
	name            string
	fixedVersion    string
	modularityLabel string
	arch            string
}

func collectPackages(criteria oracle.Criteria, tos tos) ([]detectionTypes.Detection, error) {
	pkgs, err := evalCriteria(criteria, tos)
	if err != nil {
		return nil, errors.Wrapf(err, "eval criteria")
	}

	m := map[ovalPackage][]string{}
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
	mm := map[string][]criterionTypes.Criterion{}
	for p, as := range m {
		mm[p.major] = append(mm[p.major], criterionTypes.Criterion{
			Vulnerable: true,
			Package: packageTypes.Package{
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
			Affected: &affectedTypes.Affected{
				Type:  rangeTypes.RangeTypeRPM,
				Range: []rangeTypes.Range{{LessThan: p.fixedVersion}},
				Fixed: []string{p.fixedVersion},
			},
		})
	}

	ds := make([]detectionTypes.Detection, 0, len(mm))
	for v, cs := range mm {
		ds = append(ds, detectionTypes.Detection{
			Ecosystem: detectionTypes.Ecosystem(fmt.Sprintf("%s:%s", detectionTypes.EcosystemTypeOracle, v)),
			Criteria: criteriaTypes.Criteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: cs,
			},
		})
	}
	return ds, nil
}

func evalCriteria(criteria oracle.Criteria, tos tos) ([]ovalPackage, error) {
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
		ps, err := evalCriteria(ca, tos)
		if err != nil {
			return nil, errors.Wrap(err, "eval criteria")
		}
		pkgs = append(pkgs, ps...)
	}

	// If this criteria is AND and without child criterias case. Add base (ANY) one
	if criteria.Operator == "AND" && len(criteria.Criterias) == 0 {
		pkgs = append(pkgs, ovalPackage{})
	}

	if err := evalCriterions(pkgs, tos, criteria.Criterions); err != nil {
		return nil, errors.Wrap(err, "eval criterions")
	}
	return pkgs, nil
}

func evalCriterions(pkgs []ovalPackage, tos tos, criterions []oracle.Criterion) error {
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
		switch filepath.Base(filepath.Dir(path)) {
		case "rpminfo_test":
			rpminfoTests[fetched.ID] = fetched
		case "textfilecontent54_test":
			textfileTests[fetched.ID] = fetched
		default:
			return errors.Errorf("unexpected test type. expected: %q, actual: %q", []string{"rpminfo_test", "textfilecontent54_test"}, filepath.Base(filepath.Dir(path)))
		}
		return nil
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "walk %s", testsRoot)
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

		switch filepath.Base(filepath.Dir(path)) {
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
		default:
			return errors.Errorf("unexpected object type. expected: %q, actual: %q", []string{"rpminfo_object", "textfilecontent54_object"}, filepath.Base(filepath.Dir(path)))
		}
		return nil
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "walk %s", objectsRoot)
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

		switch filepath.Base(filepath.Dir(path)) {
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
		default:
			return errors.Errorf("unexpected state type. expected: %q, actual: %q", []string{"rpminfo_state", "textfilecontent54_state"}, filepath.Base(filepath.Dir(path)))
		}
		return nil
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "walk %s", statesRoot)
	}

	return rpminfoStates, textfileStates, nil
}
