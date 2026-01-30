package oval

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necbinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcbinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
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

	defDirs, err := filepath.Glob(filepath.Join(inputDir, "*", "*", "vulnerability", "definitions"))
	if err != nil {
		return errors.Wrapf(err, "glob directories. pattern: %q", filepath.Join(inputDir, "*", "*", "vulnerability", "definitions"))
	}

	for _, defDir := range defDirs {
		rel, err := filepath.Rel(inputDir, defDir)
		if err != nil {
			return errors.Wrapf(err, "get relative path. base: %q, target: %q", inputDir, defDir)
		}

		parts, err := util.Split(strings.TrimPrefix(rel, string(os.PathSeparator)), string(os.PathSeparator), string(os.PathSeparator), string(os.PathSeparator))
		if err != nil {
			return errors.Wrapf(err, "split %s", rel)
		}

		baseDir := filepath.Join(inputDir, parts[0], parts[1], parts[2])

		log.Printf("[INFO] extract OVAL files. dir: %s", baseDir)

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
					if err := (extractor{
						inputDir: inputDir,
						baseDir:  baseDir,
						osname:   parts[0],
						version:  parts[1],
						r:        utiljson.NewJSONReader(),
					}).extract(path, options.dir); err != nil {
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

	splitted, err := util.Split(string(data.ID), "-", "-")
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZ", data.ID)
	}

	if _, err := time.Parse("2006", splitted[1]); err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZ", data.ID)
	}

	// Merge with existing data if exists.
	// This read-modify-read happens per "definitions/" directory, the files in it has CVE IDs in its names,
	// then no concurrency issue should happen in the bunch.
	// Other "definitions/" directorries are processed in sequentially in Extract function.
	// So, no locks are required here.
	filename := filepath.Join(outdir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID))
	if _, err := os.Stat(filename); err == nil {
		f, err := os.Open(filename)
		if err != nil {
			return errors.Wrapf(err, "open %s", filename)
		}
		defer f.Close()

		var base dataTypes.Data
		if err := json.UnmarshalRead(f, &base); err != nil {
			return errors.Wrapf(err, "decode %s", filename)
		}

		data.Merge(base)
	}

	if err := util.Write(filename, data, true); err != nil {
		return errors.Wrapf(err, "write %s", filename)
	}

	return nil
}

func (e extractor) buildData(def oval.Definition) (dataTypes.Data, error) {
	if !strings.HasPrefix(strings.TrimSpace(def.Metadata.Title), "CVE-") {
		return dataTypes.Data{}, errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZ", def.Metadata.Title)
	}

	id := strings.TrimSpace(def.Metadata.Title)

	es, err := func() (ecosystemTypes.Ecosystem, error) {
		switch e.osname {
		case "suse.linux.enterprise", "suse.linux.enterprise.server", "suse.linux.enterprise.desktop":
			return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, strings.Split(e.version, ".")[0])), nil
		case "suse.linux.micro", "suse.linux.enterprise.micro":
			return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeSUSELinuxMicro, strings.Split(e.version, ".")[0])), nil
		case "opensuse":
			switch e.version {
			case "tumbleweed":
				return ecosystemTypes.EcosystemTypeOpenSUSETumbleweed, nil
			default:
				return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOpenSUSE, e.version)), nil
			}
		case "opensuse.leap":
			return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOpenSUSELeap, e.version)), nil
		case "opensuse.leap.micro":
			return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOpenSUSELeapMicro, e.version)), nil
		default:
			return "", errors.Errorf("unexpected osname. expected: %q, actual: %q", []string{"suse.linux.enterprise", "suse.linux.enterprise.server", "suse.linux.enterprise.desktop", "suse.linux.micro", "suse.linux.enterprise.micro", "opensuse", "opensuse.leap", "opensuse.leap.micro"}, e.osname)
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "build ecosystem. osname: %q, version: %q", e.osname, e.version)
	}

	tag := func() segmentTypes.DetectionTag {
		switch e.osname {
		case "suse.linux.enterprise.server":
			return segmentTypes.DetectionTag("server")
		case "suse.linux.enterprise.desktop":
			return segmentTypes.DetectionTag("desktop")
		default:
			return segmentTypes.DetectionTag("")
		}
	}()

	as, v, err := buildAdvisoryAndVulnerability(def)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "build vulnerability %s", def.Metadata.Title)
	}

	t, err := e.translateCriteria(def.Criteria)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "eval criteria")
	}

	ds, err := func() ([]detectionTypes.Detection, error) {
		if t.alwaysSatisfied {
			return nil, errors.Errorf("root criteria must not be always-satisfied. id: %s", id)
		}

		if t.neverSatisfied {
			return nil, nil
		}

		if t.criteria == nil {
			return nil, errors.Errorf("unexpected nil criteria. id: %s", id)
		}
		if t.criterion != nil {
			return nil, errors.Errorf("unexpected non-nil criterion. id: %s", id)
		}

		if e.osname == "opensuse" {
			switch e.version {
			case "12.1", "12.2", "12.3":
				// These OVAL's do not include "-release" package version criterions. Force it by "openSUSE-release"
				t.criteria = &criteriaTypes.Criteria{
					Operator:  criteriaTypes.CriteriaOperatorTypeAND,
					Criterias: []criteriaTypes.Criteria{*t.criteria},
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: false,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &vcbinaryTypes.Package{
										Name: "openSUSE-release",
									},
								},
								Affected: &affectedTypes.Affected{
									Type: affectedrangeTypes.RangeTypeRPMVersionOnly,
									Range: []affectedrangeTypes.Range{
										{
											Equal: e.version,
										},
									},
								},
							},
						},
					},
				}
			default:
			}
		}

		return []detectionTypes.Detection{
			{
				Ecosystem: es,
				Conditions: func() []conditionTypes.Condition {
					return []conditionTypes.Condition{
						{
							Criteria: *t.criteria,
							Tag:      tag,
						},
					}
				}(),
			},
		}, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "build detection")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: func() []advisoryTypes.Advisory {
			advs := make([]advisoryTypes.Advisory, 0, len(as))
			for _, a := range as {
				advs = append(advs, advisoryTypes.Advisory{
					Content: a,
					Segments: []segmentTypes.Segment{
						{
							Ecosystem: es,
							Tag:       tag,
						},
					},
				})
			}
			return advs
		}(),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: v,
				Segments: []segmentTypes.Segment{
					{
						Ecosystem: es,
						Tag:       tag,
					},
				},
			},
		},
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.SUSEOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}

func buildAdvisoryAndVulnerability(def oval.Definition) ([]advisoryContentTypes.Content, vulnerabilityContentTypes.Content, error) {
	v := vulnerabilityContentTypes.Content{
		ID:          vulnerabilityContentTypes.VulnerabilityID(strings.TrimSpace(def.Metadata.Title)),
		Title:       strings.TrimSpace(def.Metadata.Title),
		Description: strings.TrimSpace(def.Metadata.Description),
		Published:   utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
		Modified:    utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Updated.Date),
	}

	if def.Metadata.Advisory.Severity != "" {
		v.Severity = append(v.Severity, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "SUSE Severity",
			Vendor: func() *string {
				s := strings.TrimSpace(def.Metadata.Advisory.Severity)
				return &s
			}(),
		})
	}

	refs := make(map[referenceTypes.Reference]struct{})

	for _, cve := range def.Metadata.Advisory.Cve {
		source, err := func() (string, error) {
			switch {
			case strings.HasSuffix(strings.TrimSpace(cve.Text), " at SUSE"),
				strings.HasPrefix(strings.TrimSpace(cve.Href), "https://www.suse.com/security/cve/"):
				return "SUSE", nil
			case strings.HasSuffix(strings.TrimSpace(cve.Text), " at NVD"):
				return "NVD", nil
			default:
				return "", errors.Errorf("unexpected CVE source. expected: %q, actual: %q, href: %q", []string{"SUSE", "NVD"}, cve.Text, cve.Href)
			}
		}()
		if err != nil {
			return nil, vulnerabilityContentTypes.Content{}, errors.Wrap(err, "determine CVE source")
		}

		refs[referenceTypes.Reference{
			Source: source,
			URL:    strings.TrimSuffix(strings.TrimSpace(cve.Href), "/"),
		}] = struct{}{}

		ss, err := buildSeverities(source, cve)
		if err != nil {
			return nil, vulnerabilityContentTypes.Content{}, errors.Wrapf(err, "build severity %s", cve.Text)
		}

		v.Severity = append(v.Severity, ss...)
	}

	for _, b := range def.Metadata.Advisory.Bugzilla {
		if !strings.HasPrefix(b.Text, "SUSE bug ") {
			return nil, vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected bugzilla text. expected prefix: %q, actual: %q", "SUSE bug ", b.Text)
		}
		refs[referenceTypes.Reference{
			Source: "SUSE",
			URL:    strings.TrimSpace(b.Href),
		}] = struct{}{}
	}

	var advs []advisoryContentTypes.Content
	for _, r := range def.Metadata.Reference {
		switch r.Source {
		case "SUSE CVE":
			refs[referenceTypes.Reference{
				Source: "SUSE",
				URL:    strings.TrimSuffix(strings.TrimSpace(r.RefURL), "/"),
			}] = struct{}{}
		case "CVE":
			refs[referenceTypes.Reference{
				Source: "CVE",
				URL:    strings.TrimSuffix(strings.TrimSpace(r.RefURL), "/"),
			}] = struct{}{}
		case "SUSE-SU":
			if r.RefID == "" {
				if r.RefURL == "" {
					continue
				}
				return nil, vulnerabilityContentTypes.Content{}, errors.New("unexpected empty SUSE-SU ID.")
			}

			advs = append(advs, advisoryContentTypes.Content{
				ID:    advisoryContentTypes.AdvisoryID(strings.TrimSpace(r.RefID)),
				Title: r.RefID,
				References: []referenceTypes.Reference{
					{
						Source: "SUSE",
						URL:    strings.TrimSpace(r.RefURL),
					},
				},
			})
		default:
			return nil, vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected reference source. expected: %q, actual: %q", []string{"SUSE CVE", "CVE", "SUSE-SU"}, r.Source)
		}
	}

	v.References = slices.Collect(maps.Keys(refs))
	return advs, v, nil
}

func buildSeverities(source string, cve oval.CVE) ([]severityTypes.Severity, error) {
	var ss []severityTypes.Severity

	if cve.Cvss3 != "" {
		_, rhs, _ := strings.Cut(strings.TrimSpace(cve.Cvss3), "/")
		switch {
		case strings.HasPrefix(rhs, "CVSS:3.0"):
			v30, err := cvssV30Types.Parse(rhs)
			if err != nil {
				return nil, errors.Wrap(err, "parse cvss3.0")
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  source,
				CVSSv30: v30,
			})
		case strings.HasPrefix(rhs, "CVSS:3.1"):
			v31, err := cvssV31Types.Parse(rhs)
			if err != nil {
				return nil, errors.Wrap(err, "parse cvss3.1")
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  source,
				CVSSv31: v31,
			})
		default:
			return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.Cvss3)
		}
	}

	if cve.Cvss4 != "" {
		_, rhs, _ := strings.Cut(strings.TrimSpace(cve.Cvss4), "/")
		switch {
		case strings.HasPrefix(rhs, "CVSS:4.0"):
			v40, err := cvssV40Types.Parse(rhs)
			if err != nil {
				return nil, errors.Wrap(err, "parse cvss4.0")
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv40,
				Source:  source,
				CVSSv40: v40,
			})
		default:
			return nil, errors.Errorf("unexpected CVSSv4 string. expected: %q, actual: %q", "<score>/CVSS:4.0/<vector>", cve.Cvss4)
		}
	}

	if cve.Impact != "" {
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: fmt.Sprintf("%s impact", source),
			Vendor: func() *string {
				s := strings.TrimSpace(cve.Impact)
				return &s
			}(),
		})
	}

	return ss, nil
}

type translated struct {
	// These flags are mutually exclusive. Only one of them can be true, at most.
	alwaysSatisfied bool
	neverSatisfied  bool

	// If one of above flags is true, these fields must be nil.
	// Also, only one of these fields can be non-nil, at most.
	criterion *criterionTypes.Criterion
	criteria  *criteriaTypes.Criteria
}

func (e extractor) translateCriteria(oc oval.Criteria) (translated, error) {
	if len(oc.Criterias) == 0 && len(oc.Criterions) == 0 {
		return translated{neverSatisfied: true}, nil
	}

	ts := make([]translated, 0, len(oc.Criterias)+len(oc.Criterions))
	for _, child := range oc.Criterias {
		t, err := e.translateCriteria(child)
		if err != nil {
			return translated{}, errors.Wrapf(err, "walk criteria")
		}
		ts = append(ts, t)
	}

	// Some definitions have duplicated criterions.
	// For example, opensuse 12.1, "oval:org.opensuse.security:def: 20125252"
	cns := make(map[string]oval.Criterion)
	for _, child := range oc.Criterions {
		cns[child.TestRef] = child
	}
	for _, child := range cns {
		t, err := e.translateCriterion(child)
		if err != nil {
			return translated{}, errors.Wrapf(err, "translate criterion")
		}
		ts = append(ts, t)
	}

	var c criteriaTypes.Criteria
	filtered := make([]translated, 0, len(ts))

	switch oc.Operator {
	case "OR":
		c.Operator = criteriaTypes.CriteriaOperatorTypeOR
		for _, child := range ts {
			switch {
			case child.alwaysSatisfied:
				return translated{alwaysSatisfied: true}, nil
			case child.neverSatisfied:
			default:
				filtered = append(filtered, child)
			}
		}

		if len(filtered) == 0 {
			// All children are never-satisfied
			return translated{neverSatisfied: true}, nil
		}
	case "AND":
		c.Operator = criteriaTypes.CriteriaOperatorTypeAND
		for _, child := range ts {
			switch {
			case child.alwaysSatisfied:
			case child.neverSatisfied:
				return translated{neverSatisfied: true}, nil
			default:
				filtered = append(filtered, child)
			}
		}

		if len(filtered) == 0 {
			// All children are always-satisfied
			return translated{alwaysSatisfied: true}, nil
		}
	default:
		return translated{}, errors.Errorf("unexpected oval criteria operator. expected: %q, actual: %q", []string{"OR", "AND"}, oc.Operator)
	}

	for _, child := range filtered {
		switch {
		case child.criteria != nil && child.criterion != nil:
			return translated{}, errors.Errorf("unexpected non-nil criteria and criterion. OVAL criteria: %+v", oc)
		case child.criteria == nil && child.criterion == nil:
			return translated{}, errors.Errorf("unexpected nil criteria and criterion. OVAL criteria: %+v", oc)
		case child.criteria != nil:
			c.Criterias = append(c.Criterias, *child.criteria)
		case child.criterion != nil:
			c.Criterions = append(c.Criterions, *child.criterion)
		default:
		}
	}

	return translated{
		criteria: &c,
	}, nil
}

func (e extractor) translateCriterion(oc oval.Criterion) (translated, error) {
	var t oval.RpminfoTest
	if err := e.r.Read(filepath.Join(e.baseDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", oc.TestRef)), e.inputDir, &t); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// There was a case that a special build did not have its own release package (by mistake),
			// then uname criterions was used only for it ("oval:org.opensuse.security:def:20258040" of suse.linux.enterprise.server.12-affected.xml).
			// Because it's not used for normal SLES and openSUSE products, we only do existence check here
			// and treat it as NEVER SATISFIED.
			if _, err := os.Stat(filepath.Join(e.baseDir, "tests", "uname_test", fmt.Sprintf("%s.json", oc.TestRef))); err != nil {
				return translated{}, err
			}
			return translated{neverSatisfied: true}, nil
		}

		return translated{}, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "tests", "rpminfo_test", oc.TestRef))
	}

	var o oval.RpminfoObject
	if err := e.r.Read(filepath.Join(e.baseDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", t.Object.ObjectRef)), e.inputDir, &o); err != nil {
		return translated{}, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "objects", "rpminfo_object", t.Object.ObjectRef))
	}

	var s oval.RpminfoState
	if err := e.r.Read(filepath.Join(e.baseDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", t.State.StateRef)), e.inputDir, &s); err != nil {
		return translated{}, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "states", "rpminfo_state", t.State.StateRef))
	}

	if o.Name == "" {
		return translated{}, errors.Errorf("unexpected rpminfo_object name. name: %q", o.Name)
	}

	if s.SignatureKeyid.Text != "" {
		if s.Version.Text != "" || s.Evr.Text != "" || s.Arch.Text != "" {
			return translated{}, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state version: %q, evr: %q arch: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text, s.Arch.Text)
		}
		return translated{alwaysSatisfied: true}, nil
	}

	if strings.HasSuffix(oc.Comment, "is not affected") {
		// sanity check
		if s.Version.Text != "0" || s.Version.Operation != "equals" {
			return translated{}, errors.Errorf(`unexpected rpminfo_state for "is not affected". test: %s, expected: %q %q, actual: %q %q`, oc.TestRef, "equals", "0", s.Version.Operation, s.Version.Text)
		}
		return translated{neverSatisfied: true}, nil
	}

	switch {
	case s.Version.Text != "" && s.Evr.Text != "":
		return translated{}, errors.Errorf("only version or evr should be set. test: %s, check: %q, version: %q, evr: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text)
	case s.Version.Text == "" && s.Evr.Text == "":
		return translated{}, errors.Errorf("at least one of version or evr must be set. test: %s, check: %q, version: %q, evr: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text)
	case s.Version.Text != "":
		tr, err := e.translateVersionCriterion(oc, t, o, s)
		if err != nil {
			return translated{}, errors.Wrapf(err, "translate version criterion")
		}
		return tr, nil
	case s.Evr.Text != "":
		tr, err := e.translateEVRCriterion(oc, t, o, s)
		if err != nil {
			return translated{}, errors.Wrapf(err, "translate EVR criterion")
		}
		return tr, nil
	default:
		return translated{}, errors.Errorf("unexpected combination. test: %s, check: %q, version: %q, evr: %q", oc.TestRef, t.Check, s.Version.Text, s.Evr.Text)
	}
}

func (e extractor) translateVersionCriterion(oc oval.Criterion, t oval.RpminfoTest, o oval.RpminfoObject, s oval.RpminfoState) (translated, error) {
	switch t.Check {
	case "at least one":
		if s.Arch.Text != "" {
			return translated{}, errors.Errorf("unexpected arch. test: %s, check: %q, expected: %q, actual: %q", oc.TestRef, t.Check, "", s.Arch.Text)
		}

		if s.Version.Operation != "equals" {
			return translated{}, errors.Errorf("unexpected operation. test: %s, expected: %q, actual: %q", oc.TestRef, "equals", s.Version.Operation)
		}

		switch e.osname {
		case "suse.linux.enterprise.server":
			if o.Name == "sled-release" {
				return translated{neverSatisfied: true}, nil
			}
		case "suse.linux.enterprise.desktop":
			if o.Name == "sles-release" {
				return translated{neverSatisfied: true}, nil
			}
		default:
		}

		return translated{
			criterion: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: false,
					Package: criterionpackageTypes.Package{
						Type: criterionpackageTypes.PackageTypeBinary,
						Binary: &vcbinaryTypes.Package{
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
			},
		}, nil
	default:
		return translated{}, errors.Errorf("unexpected rpminfo_test check. test: %s, expected: %q, actural: %q", oc.TestRef, "at least one", t.Check)
	}
}

func (e extractor) translateEVRCriterion(oc oval.Criterion, t oval.RpminfoTest, o oval.RpminfoObject, s oval.RpminfoState) (translated, error) {
	pkg, err := func() (criterionpackageTypes.Package, error) {
		if s.Arch.Text == "" {
			return criterionpackageTypes.Package{
				Type: criterionpackageTypes.PackageTypeBinary,
				Binary: &vcbinaryTypes.Package{
					Name: o.Name,
				},
			}, nil
		}
		if s.Arch.Operation != "pattern match" {
			return criterionpackageTypes.Package{}, errors.Errorf("unexpected rpminfo_state arch operation. test: %s, expected: %q, actual: %q", oc.TestRef, "pattern match", s.Arch.Operation)
		}

		return criterionpackageTypes.Package{
			Type: criterionpackageTypes.PackageTypeBinary,
			Binary: &vcbinaryTypes.Package{
				Name:          o.Name,
				Architectures: strings.Split(strings.TrimPrefix(strings.TrimSuffix(s.Arch.Text, ")"), "("), "|"),
			},
		}, nil
	}()
	if err != nil {
		return translated{}, errors.Wrapf(err, "build package")
	}

	switch s.Evr.Operation {
	case "less than":
		return translated{
			criterion: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus: &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassFixed,
					},
					Package: pkg,
					Affected: &affectedTypes.Affected{
						Type: affectedrangeTypes.RangeTypeRPM,
						Range: []affectedrangeTypes.Range{{
							LessThan: s.Evr.Text,
						}},
					},
				},
			},
		}, nil
	case "equals":
		// Should be siblings of kernel-livepatch patterns, sanity check.
		if !strings.HasPrefix(o.Name, "kernel-") {
			return translated{}, errors.Errorf("unexpected rpminfo_object name. test: %s, expected: %q, actual: %q", oc.TestRef, "kernel-*", o.Name)
		}

		return translated{
			criterion: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus: &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassUnknown,
					},
					Package: pkg,
					Affected: &affectedTypes.Affected{
						Type: affectedrangeTypes.RangeTypeRPM,
						Range: []affectedrangeTypes.Range{{
							Equal: s.Evr.Text,
						}},
					},
				},
			},
		}, nil
	case "greater than":
		if s.Evr.Text != "0:0-0" {
			return translated{}, errors.Errorf("unexpected rpminfo_state evr. test: %s, expected: %q, actual: %q", oc.TestRef, "0:0-0", s.Evr.Text)
		}

		return translated{
			criterion: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus: &fixstatusTypes.FixStatus{
						Class: fixstatusTypes.ClassUnfixed,
					},
					Package: pkg,
				},
			},
		}, nil
	case "greater than or equal":
		switch t.Check {
		case "at least one", "all":
			// This combination only happens for "*-release" rpms.
			// Mainly used in openSUSE Tumbleweed, for example, oval:org.opensuse.security:def:20011267
			// The test looks like this:
			// 	"id": "oval:org.opensuse.security:tst:2009634834",
			//  "version": "1",
			//  "comment": "openSUSE-release is >=20210101",
			// Also it is used in SLES, e.g. oval:org.opensuse.security:def:20042771 in suse.linux.enterprise.11-affected.xml
			// For sanity check, make sure the package has "-release" suffix.
			// This is release version restriction only and actual vulnerable package information are
			// provided in other criterias/criterions. So we translate it to Vulnerable false.
			if !strings.HasSuffix(o.Name, "-release") {
				return translated{}, errors.Errorf("unexpected rpminfo_object name. test: %s, expected: %q, actual: %q", oc.TestRef, "*-release", o.Name)
			}

			return translated{
				criterion: &criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: false,
						Package:    pkg,
						Affected: &affectedTypes.Affected{
							Type: affectedrangeTypes.RangeTypeRPM,
							Range: []affectedrangeTypes.Range{{
								GreaterEqual: s.Evr.Text,
							}},
						},
					},
				},
			}, nil
		case "none satisfy":
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
				return translated{}, errors.Errorf("unexpected rpminfo_object. test: %s, rpminfo_test check: %q, expected: %q, rpminfo_object name: %q", oc.TestRef, t.Check, []string{"kernel-livepatch-*", "kgraft-patch-*"}, o.Name)
			}
			if s.Evr.Operation != "greater than or equal" {
				return translated{}, errors.Errorf("unexpected combination. test: %s, rpminfo_test check: %q, rpminfo_state evr: %q, operation: %q", oc.TestRef, t.Check, s.Evr.Text, s.Evr.Operation)
			}

			return translated{
				criteria: &criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: false,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &vcbinaryTypes.Package{
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
				},
			}, nil
		default:
			return translated{}, errors.Errorf("unexpected rpminfo_test check. test: %s, expected: %q, actual: %q", oc.TestRef, []string{"at least one", "all", "none satisfy"}, t.Check)
		}
	default:
		return translated{}, errors.Errorf("unexpected evr operation. test: %s, check: %q, expected: %q, actual: %q", oc.TestRef, "at least one", []string{"less than", "equals", "greater than", "greater than or equal"}, s.Evr.Operation)
	}
}
