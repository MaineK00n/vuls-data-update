package cvrf

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/errors"

	defenderandroidversion "github.com/MaineK00n/go-microsoft-version/defender/android"
	defenderiosversion "github.com/MaineK00n/go-microsoft-version/defender/ios"
	defenderiotversion "github.com/MaineK00n/go-microsoft-version/defender/iot"
	defenderlinuxversion "github.com/MaineK00n/go-microsoft-version/defender/linux"
	defendermacversion "github.com/MaineK00n/go-microsoft-version/defender/mac"
	defendersiversion "github.com/MaineK00n/go-microsoft-version/defender/securityintelligence"
	defenderwindowsversion "github.com/MaineK00n/go-microsoft-version/defender/windows"
	dotnetcoreversion "github.com/MaineK00n/go-microsoft-version/dotnet/core"
	edgeversion "github.com/MaineK00n/go-microsoft-version/edge"
	exchangeversion "github.com/MaineK00n/go-microsoft-version/exchange"
	officemacversion "github.com/MaineK00n/go-microsoft-version/office/mac"
	officewindowsversion "github.com/MaineK00n/go-microsoft-version/office/windows"
	sharepointversion "github.com/MaineK00n/go-microsoft-version/sharepoint"
	sqlserverversion "github.com/MaineK00n/go-microsoft-version/sqlserver"
	teamsandroidversion "github.com/MaineK00n/go-microsoft-version/teams/android"
	teamsclientversion "github.com/MaineK00n/go-microsoft-version/teams/client"
	teamsdesktopversion "github.com/MaineK00n/go-microsoft-version/teams/desktop"
	teamsiosversion "github.com/MaineK00n/go-microsoft-version/teams/ios"
	teamsmacversion "github.com/MaineK00n/go-microsoft-version/teams/mac"
	visualstudioversion "github.com/MaineK00n/go-microsoft-version/visualstudio"
	vscodeversion "github.com/MaineK00n/go-microsoft-version/vscode"
	windowsversion "github.com/MaineK00n/go-microsoft-version/windows"

	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssv30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssv31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/cvrf"
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "cvrf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft CVRF")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		e := extractor{
			inputDir: args,
			r:        utiljson.NewJSONReader(),
		}

		var c cvrf.CVRF
		if err := e.r.Read(path, e.inputDir, &c); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		if len(c.Vulnerability) == 0 {
			return nil
		}

		datas, kbs, err := e.extract(c)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		for _, data := range datas {
			var dir string
			switch {
			case strings.HasPrefix(string(data.ID), "CVE-"):
				splitted, err := util.Split(string(data.ID), "-", "-")
				if err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", data.ID)
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", data.ID)
				}
				dir = filepath.Join("CVE", splitted[1])
			case strings.HasPrefix(string(data.ID), "ADV"):
				if len(data.ID) < 5 {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "ADVyy\\d{4,}", data.ID)
				}
				yy := string(data.ID)[3:5]
				t, err := time.Parse("06", yy)
				if err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ADVyy\\d{4,}", data.ID)
				}
				dir = filepath.Join("ADV", fmt.Sprintf("%d", t.Year()))
			default:
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "ADVyy\\d{4,}"}, data.ID)
			}

			if err := util.Write(filepath.Join(options.dir, "data", dir, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", dir, fmt.Sprintf("%s.json", data.ID)))
			}
		}

		for _, kb := range kbs {
			if kb.KBID == "" {
				continue
			}

			if len(kb.KBID) <= 3 {
				return errors.Errorf("unexpected KBID format. expected: len > 3, actual: %q", kb.KBID)
			}

			filename := filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID))
			if _, err := os.Stat(filename); err == nil {
				if err := func() error {
					f, err := os.Open(filename)
					if err != nil {
						return errors.Wrapf(err, "open %s", filename)
					}
					defer f.Close()

					var base microsoftkbTypes.KB
					if err := json.UnmarshalRead(f, &base); err != nil {
						return errors.Wrapf(err, "unmarshal %s", filename)
					}

					kb.Merge(base)

					return nil
				}(); err != nil {
					return errors.Wrapf(err, "merge %s", filename)
				}
			}

			if err := util.Write(filename, kb, true); err != nil {
				return errors.Wrapf(err, "write %s", filename)
			}
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftCVRF,
		Name: func() *string { s := "Microsoft CVRF"; return &s }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
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

func (e extractor) extract(c cvrf.CVRF) ([]dataTypes.Data, []microsoftkbTypes.KB, error) {
	products := collectProducts(c.ProductTree)

	var datas []dataTypes.Data
	kbm := make(map[string]microsoftkbTypes.KB)

	for _, v := range c.Vulnerability {
		var description string
		for _, note := range v.Notes.Note {
			if note.Type == "Description" && strings.TrimSpace(note.Text) != "" {
				description = strings.TrimSpace(note.Text)
				break
			}
		}

		productInfoMap, err := buildProductInfoMap(v)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "build product info map for %s", v.CVE)
		}

		var advisories []advisoryTypes.Advisory
		var vulns []vulnerabilityTypes.Vulnerability

		switch {
		case strings.HasPrefix(v.CVE, "CVE-"):
			vulns, err = buildVulnerabilities(v, c, products, productInfoMap, description)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "build vulnerabilities for %s", v.CVE)
			}
		case strings.HasPrefix(v.CVE, "ADV"):
			advisories, err = buildAdvisories(v, c, products, productInfoMap, description)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "build advisories for %s", v.CVE)
			}
		default:
			return nil, nil, errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"CVE-", "ADV"}, v.CVE)
		}

		conditionsByEcosystem, err := buildDetections(v, products)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "build detections for %s", v.CVE)
		}

		if err := e.collectKBs(v, products, kbm); err != nil {
			return nil, nil, errors.Wrapf(err, "collect KBs for %s", v.CVE)
		}

		datas = append(datas, dataTypes.Data{
			ID:              dataTypes.RootID(v.CVE),
			Advisories:      advisories,
			Vulnerabilities: vulns,
			Detections: func() []detectionTypes.Detection {
				if len(conditionsByEcosystem) == 0 {
					return nil
				}
				ds := make([]detectionTypes.Detection, 0, len(conditionsByEcosystem))
				for eco, conds := range conditionsByEcosystem {
					ds = append(ds, detectionTypes.Detection{
						Ecosystem:  eco,
						Conditions: conds,
					})
				}
				return ds
			}(),
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftCVRF,
				Raws: e.r.Paths(),
			},
		})
	}

	return datas, slices.Collect(maps.Values(kbm)), nil
}
func collectProducts(pt cvrf.ProductTree) map[string]string {
	m := make(map[string]string)
	for _, p := range pt.FullProductName {
		m[p.ProductID] = p.Text
	}
	collectBranch(pt.Branch, m)
	return m
}

func collectBranch(b cvrf.Branch, m map[string]string) {
	for _, p := range b.FullProductName {
		m[p.ProductID] = p.Text
	}
	for _, child := range b.Branch {
		collectBranch(child, m)
	}
}

type productInfo struct {
	status        string
	severity      string
	impact        string
	exploitStatus string
	cvss          *severityTypes.Severity
}

func buildProductInfoMap(v cvrf.Vulnerability) (map[string]productInfo, error) {
	productInfoMap := make(map[string]productInfo)
	for _, pid := range v.ProductStatuses.Status.ProductID {
		pi := productInfoMap[pid]
		pi.status = v.ProductStatuses.Status.Type
		productInfoMap[pid] = pi
	}
	for _, t := range v.Threats.Threat {
		if t.ProductID == "" || t.Description == "" {
			continue
		}
		pi := productInfoMap[t.ProductID]
		switch t.Type {
		case "Severity":
			pi.severity = t.Description
		case "Impact":
			pi.impact = t.Description
		case "Exploit Status":
			pi.exploitStatus = t.Description
		default:
			return nil, errors.Errorf("unexpected threat type. expected: %q, actual: %q", []string{"Severity", "Impact", "Exploit Status"}, t.Type)
		}
		productInfoMap[t.ProductID] = pi
	}
	for _, s := range v.CVSSScoreSets.ScoreSet {
		if s.Vector == "" || s.ProductID == "" {
			continue
		}
		pi := productInfoMap[s.ProductID]
		switch {
		case strings.HasPrefix(s.Vector, "CVSS:3.0/"):
			cvss, err := cvssv30Types.Parse(s.Vector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse CVSS v3.0 vector %q for %s", s.Vector, v.CVE)
			}
			pi.cvss = &severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  "secure@microsoft.com",
				CVSSv30: cvss,
			}
		case strings.HasPrefix(s.Vector, "CVSS:3.1/"):
			cvss, err := cvssv31Types.Parse(s.Vector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse CVSS v3.1 vector %q for %s", s.Vector, v.CVE)
			}
			pi.cvss = &severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  "secure@microsoft.com",
				CVSSv31: cvss,
			}
		default:
			return nil, errors.Errorf("unexpected CVSS vector format. expected: %q, actual: %q", []string{"CVSS:3.0/*", "CVSS:3.1/*"}, s.Vector)
		}
		productInfoMap[s.ProductID] = pi
	}
	return productInfoMap, nil
}

func buildVulnerabilities(v cvrf.Vulnerability, c cvrf.CVRF, products map[string]string, productInfoMap map[string]productInfo, description string) ([]vulnerabilityTypes.Vulnerability, error) {
	cwes := buildCWEs(v)
	refs := buildReferences(v.CVE)
	published := utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05"}, c.DocumentTracking.InitialReleaseDate)
	modified := utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05"}, c.DocumentTracking.CurrentReleaseDate)

	var vulns []vulnerabilityTypes.Vulnerability
	for _, pid := range v.ProductStatuses.Status.ProductID {
		pi := productInfoMap[pid]
		if pi.status != "Known Affected" {
			return nil, errors.Errorf("unexpected product status type. expected: %q, actual: %q, product: %q, id: %q", "Known Affected", pi.status, pid, v.CVE)
		}

		productName, ok := products[pid]
		if !ok {
			return nil, errors.Errorf("product ID %q not found in product tree for %s", pid, v.CVE)
		}

		if isCBLMarinerOrAzureLinux(productName) {
			continue
		}

		vc := vulnerabilityContentTypes.Content{
			ID:          vulnerabilityContentTypes.VulnerabilityID(v.CVE),
			Title:       v.Title,
			Description: description,
			Severity:    buildSeverities(pi),
			CWE:         cwes,
			References:  refs,
			Published:   published,
			Modified:    modified,
			Optional:    buildOptional(pi),
		}
		vulns = appendOrMergeSegment(vulns,
			vulnerabilityTypes.Vulnerability{
				Content:  vc,
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft, Tag: segmentTypes.DetectionTag(productName)}},
			},
			func(item vulnerabilityTypes.Vulnerability) int {
				return vulnerabilityContentTypes.Compare(item.Content, vc)
			},
			func(item *vulnerabilityTypes.Vulnerability) *[]segmentTypes.Segment { return &item.Segments },
		)
	}

	// If all products were CBL-Mariner/Azure Linux, emit product-independent metadata.
	if len(vulns) == 0 {
		vulns = append(vulns, vulnerabilityTypes.Vulnerability{
			Content: vulnerabilityContentTypes.Content{
				ID:          vulnerabilityContentTypes.VulnerabilityID(v.CVE),
				Title:       v.Title,
				Description: description,
				CWE:         cwes,
				References:  refs,
				Published:   published,
				Modified:    modified,
			},
		})
	}

	return vulns, nil
}

func buildAdvisories(v cvrf.Vulnerability, c cvrf.CVRF, products map[string]string, productInfoMap map[string]productInfo, description string) ([]advisoryTypes.Advisory, error) {
	cwes := buildCWEs(v)
	refs := buildReferences(v.CVE)
	published := utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05"}, c.DocumentTracking.InitialReleaseDate)
	modified := utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05"}, c.DocumentTracking.CurrentReleaseDate)

	var advisories []advisoryTypes.Advisory
	for _, pid := range v.ProductStatuses.Status.ProductID {
		pi := productInfoMap[pid]
		if pi.status != "Known Affected" {
			return nil, errors.Errorf("unexpected product status type. expected: %q, actual: %q, product: %q, id: %q", "Known Affected", pi.status, pid, v.CVE)
		}

		productName, ok := products[pid]
		if !ok {
			return nil, errors.Errorf("product ID %q not found in product tree for %s", pid, v.CVE)
		}

		if isCBLMarinerOrAzureLinux(productName) {
			continue
		}

		ac := advisoryContentTypes.Content{
			ID:          advisoryContentTypes.AdvisoryID(v.CVE),
			Title:       v.Title,
			Description: description,
			Severity:    buildSeverities(pi),
			CWE:         cwes,
			References:  refs,
			Published:   published,
			Modified:    modified,
			Optional:    buildOptional(pi),
		}
		advisories = appendOrMergeSegment(advisories,
			advisoryTypes.Advisory{
				Content:  ac,
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft, Tag: segmentTypes.DetectionTag(productName)}},
			},
			func(item advisoryTypes.Advisory) int {
				return advisoryContentTypes.Compare(item.Content, ac)
			},
			func(item *advisoryTypes.Advisory) *[]segmentTypes.Segment { return &item.Segments },
		)
	}

	// If all products were CBL-Mariner/Azure Linux, emit product-independent metadata.
	if len(advisories) == 0 {
		advisories = append(advisories, advisoryTypes.Advisory{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(v.CVE),
				Title:       v.Title,
				Description: description,
				CWE:         cwes,
				References:  refs,
				Published:   published,
				Modified:    modified,
			},
		})
	}

	return advisories, nil
}

func buildCWEs(v cvrf.Vulnerability) []cweTypes.CWE {
	if v.CWE == nil || v.CWE.ID == "" {
		return nil
	}
	return []cweTypes.CWE{{
		Source: "secure@microsoft.com",
		CWE:    []string{v.CWE.ID},
	}}
}

func buildReferences(id string) []referenceTypes.Reference {
	return []referenceTypes.Reference{{
		Source: "secure@microsoft.com",
		URL:    fmt.Sprintf("https://msrc.microsoft.com/update-guide/vulnerability/%s", id),
	}}
}

func buildSeverities(pi productInfo) []severityTypes.Severity {
	var sevs []severityTypes.Severity
	if pi.severity != "" {
		sevs = append(sevs, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "secure@microsoft.com",
			Vendor: &pi.severity,
		})
	}
	if pi.cvss != nil {
		sevs = append(sevs, *pi.cvss)
	}
	return sevs
}

func buildOptional(pi productInfo) map[string]any {
	m := make(map[string]any)
	if pi.impact != "" {
		m["impact"] = pi.impact
	}
	if pi.exploitStatus != "" {
		m["exploit_status"] = pi.exploitStatus
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func appendOrMergeSegment[T any](
	items []T,
	newItem T,
	compare func(T) int,
	getSegments func(*T) *[]segmentTypes.Segment,
) []T {
	for i := range items {
		if compare(items[i]) == 0 {
			dst := getSegments(&items[i])
			for _, seg := range *getSegments(&newItem) {
				if !slices.ContainsFunc(*dst, func(s segmentTypes.Segment) bool {
					return segmentTypes.Compare(s, seg) == 0
				}) {
					*dst = append(*dst, seg)
				}
			}
			return items
		}
	}
	return append(items, newItem)
}

func buildDetections(v cvrf.Vulnerability, products map[string]string) (map[ecosystemTypes.Ecosystem][]conditionTypes.Condition, error) {
	conditionsByEcosystem := make(map[ecosystemTypes.Ecosystem][]conditionTypes.Condition)

	for _, r := range v.Remediations.Remediation {
		switch r.Type {
		case "Vendor Fix":
			for _, pid := range r.ProductID {
				productName, ok := products[pid]
				if !ok {
					return nil, errors.Errorf("product ID %q not found in product tree for %s", pid, v.CVE)
				}

				if isCBLMarinerOrAzureLinux(productName) {
					continue
				}

				tag := segmentTypes.DetectionTag(productName)
				criterionProductName := microsoftutil.NormalizeProductName(productName)

				kbCriterion := buildKBCriterion(criterionProductName, r.Description)
				fixedBuildCriterion, err := buildFixedBuildCriterion(v.CVE, criterionProductName, r.FixedBuild)
				if err != nil {
					return nil, errors.Wrap(err, "build fixed build criterion")
				}

				if kbCriterion == nil && fixedBuildCriterion == nil {
					continue
				}

				var cns []criterionTypes.Criterion
				if kbCriterion != nil {
					cns = append(cns, *kbCriterion)
				}
				if fixedBuildCriterion != nil {
					cns = append(cns, *fixedBuildCriterion)
				}

				conditions := conditionsByEcosystem[ecosystemTypes.EcosystemTypeMicrosoft]
				for _, cn := range cns {
					switch idx := slices.IndexFunc(conditions, func(c conditionTypes.Condition) bool {
						return c.Tag == tag
					}); idx {
					case -1:
						conditions = append(conditions, conditionTypes.Condition{
							Criteria: criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: []criterionTypes.Criterion{cn}},
							Tag:      tag,
						})
					default:
						if !slices.ContainsFunc(conditions[idx].Criteria.Criterions, func(e criterionTypes.Criterion) bool {
							return criterionTypes.Compare(e, cn) == 0
						}) {
							conditions[idx].Criteria.Criterions = append(conditions[idx].Criteria.Criterions, cn)
						}
					}
				}
				conditionsByEcosystem[ecosystemTypes.EcosystemTypeMicrosoft] = conditions
			}
		case "Release Notes", "Known Issue", "Mitigation", "Workaround":
		default:
			return nil, errors.Errorf("unexpected remediation type. expected: %q, actual: %q", []string{"Vendor Fix", "Release Notes", "Known Issue", "Mitigation", "Workaround"}, r.Type)
		}
	}

	return conditionsByEcosystem, nil
}
func buildFixedBuildCriterion(cveID, productName, rawFixedBuild string) (*criterionTypes.Criterion, error) {
	// Generic cleanup
	fixedBuild := strings.TrimSpace(rawFixedBuild)
	fixedBuild = strings.TrimRight(fixedBuild, ".")
	fixedBuild = strings.TrimPrefix(fixedBuild, "Fixed Version ")

	// Remove zero-width spaces (U+200B)
	fixedBuild = strings.ReplaceAll(fixedBuild, "\u200b", "")

	// Apply FixedBuild overrides for known data issues
	if fb, ok := fixedBuildOverrides[[3]string{cveID, productName, fixedBuild}]; ok {
		fixedBuild = fb
	}

	if fixedBuild == "" {
		return nil, nil
	}

	// Skip non-version values that appear in raw CVRF FixedBuild fields:
	//  - Values not starting with a digit: URLs (e.g. "https://aka.ms/..."),
	//    descriptive text (e.g. "App Build 14.43.49498, Platform Build 14.0.49494"),
	//    prefixed versions (e.g. "v1.001", "V1.002", "OMI Version 1.6.8-1"),
	//    package names (e.g. "regex-1.8.4", "h2-0.3.26"), KB references (e.g. "KB5032921")
	//  - Placeholder versions containing "x" (e.g. "15.0.5415.xxxxxx", "5.64.x")
	//  - Values without dots that are not parseable version numbers (e.g. "25060212643")
	if fixedBuild[0] < '0' || fixedBuild[0] > '9' || strings.Contains(fixedBuild, "x") || !strings.Contains(fixedBuild, ".") {
		return nil, nil
	}

	rt, err := func() (rangeTypes.RangeType, error) {
		switch productName {
		// Microsoft Defender for Endpoint for Android
		case "Microsoft Defender for Endpoint for Android":
			if _, err := defenderandroidversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defenderandroidversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderAndroid, nil

		// Microsoft Defender for Endpoint for iOS
		case "Microsoft Defender for Endpoint for iOS":
			if _, err := defenderiosversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defenderiosversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderIOS, nil

		// Microsoft Defender for IoT
		case "Microsoft Defender for IoT":
			if _, err := defenderiotversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defenderiotversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderIoT, nil

		// Microsoft Defender for Endpoint for Linux
		case "Microsoft Defender for Endpoint for Linux":
			if _, err := defenderlinuxversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defenderlinuxversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderLinux, nil

		// Microsoft Defender for Endpoint for Mac
		case "Microsoft Defender for Endpoint for Mac":
			if _, err := defendermacversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defendermacversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderMac, nil

		// Microsoft Defender Security Intelligence Updates
		case "Microsoft Defender Security Intelligence Updates":
			if _, err := defendersiversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defendersiversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderSecurityIntelligence, nil

		// Windows Defender Antimalware Platform
		case "Windows Defender Antimalware Platform":
			if _, err := defenderwindowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "defenderwindowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDefenderWindows, nil

		// Microsoft Defender for Endpoint for Windows (FixedBuild is the Windows OS build number)
		case "Microsoft Defender for Endpoint for Windows on Windows 10 Version 1607 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1607 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1809 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1809 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1809 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1909 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1909 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 1909 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 20H2 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 20H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H1 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H1 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H1 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H2 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 21H2 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 22H2 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 22H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 Version 22H2 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 for 32-bit Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 10 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 22H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 22H2 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 23H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 23H2 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 21H2 for ARM64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows 11 Version 21H2 for x64-based Systems",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2012",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2012 (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2012 R2",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2012 R2 (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2016",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2016 (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2019",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2019 (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2022",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2022 (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server 2022, 23H2 Edition (Server Core installation)",
			"Microsoft Defender for Endpoint for Windows on Windows Server, Version 20H2 (Server Core installation)":
			if _, err := windowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "windowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftWindows, nil

		// Microsoft Defender for Endpoint EDR sensor (FixedBuild is Windows-style version, e.g. "10.8047.22439")
		case "Microsoft Defender for Endpoint EDR sensor on Windows Server 2012 R2",
			"Microsoft Defender for Endpoint EDR sensor on Windows Server 2012 R2 (Server Core installation)",
			"Microsoft Defender for Endpoint EDR sensor on Windows Server 2016",
			"Microsoft Defender for Endpoint EDR sensor on Windows Server 2016 (Server Core installation)":
			if _, err := windowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "windowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftWindows, nil

		// .NET Core / .NET 5+
		case ".NET 5.0",
			".NET 6.0",
			".NET 6.0 installed on Linux",
			".NET 6.0 installed on Mac OS",
			".NET 6.0 installed on Windows",
			".NET 7.0",
			".NET 8.0",
			".NET 8.0 installed on Linux",
			".NET 8.0 installed on Mac OS",
			".NET 8.0 installed on Windows",
			".NET 9.0 installed on Linux",
			".NET 9.0 installed on Mac OS",
			".NET 9.0 installed on Windows",
			".NET 10.0 installed on Linux",
			".NET 10.0 installed on Mac OS",
			".NET 10.0 installed on Windows",
			".NET Core 2.1",
			".NET Core 3.1":
			if _, err := dotnetcoreversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "dotnetcoreversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftDotNetCore, nil

		// Microsoft Edge (Chromium-based)
		case "Microsoft Edge (Chromium-based)",
			"Microsoft Edge (Chromium-based) Extended Stable":
			if _, err := edgeversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "edgeversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftEdge, nil

		// Microsoft Edge (Chromium-based) in IE Mode (FixedBuild is the Windows OS build number)
		case "Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1809 for 32-bit Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1809 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1809 for x64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1909 for 32-bit Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1909 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1909 for x64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 2004 for 32-bit Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 2004 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 2004 for x64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 20H2 for 32-bit Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 20H2 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 21H1 for 32-bit Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 21H1 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 21H1 for x64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 11 Version 21H2 for ARM64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows 11 Version 21H2 for x64-based Systems",
			"Microsoft Edge (Chromium-based) in IE Mode on Windows Server 2019":
			if _, err := windowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "windowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftWindows, nil

		// Microsoft Exchange Server
		case "Microsoft Exchange Server 2013 Cumulative Update 23",
			"Microsoft Exchange Server 2016 Cumulative Update 19",
			"Microsoft Exchange Server 2016 Cumulative Update 20",
			"Microsoft Exchange Server 2016 Cumulative Update 21",
			"Microsoft Exchange Server 2016 Cumulative Update 22",
			"Microsoft Exchange Server 2016 Cumulative Update 23",
			"Microsoft Exchange Server 2019 Cumulative Update 10",
			"Microsoft Exchange Server 2019 Cumulative Update 11",
			"Microsoft Exchange Server 2019 Cumulative Update 12",
			"Microsoft Exchange Server 2019 Cumulative Update 13",
			"Microsoft Exchange Server 2019 Cumulative Update 14",
			"Microsoft Exchange Server 2019 Cumulative Update 15",
			"Microsoft Exchange Server 2019 Cumulative Update 8",
			"Microsoft Exchange Server 2019 Cumulative Update 9",
			"Microsoft Exchange Server Subscription Edition RTM":
			if _, err := exchangeversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "exchangeversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftExchange, nil

		// Microsoft Office for Mac
		case "Microsoft Office 2019 for Mac",
			"Microsoft Office for Mac",
			"Microsoft Office LTSC for Mac 2021",
			"Microsoft Office LTSC for Mac 2024":
			if _, err := officemacversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "officemacversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftOfficeMac, nil

		// Microsoft Office for Windows
		case "Microsoft Excel 2013 RT Service Pack 1",
			"Microsoft Excel 2013 Service Pack 1 (32-bit editions)",
			"Microsoft Excel 2013 Service Pack 1 (64-bit editions)",
			"Microsoft Excel 2016 (32-bit edition)",
			"Microsoft Excel 2016 (64-bit edition)",
			"Microsoft Excel 2016 Click-to-Run (C2R) for 32-bit editions",
			"Microsoft Excel 2016 Click-to-Run (C2R) for 64-bit editions",
			"Microsoft Office 2013 Click-to-Run (C2R) for 32-bit editions",
			"Microsoft Office 2013 Click-to-Run (C2R) for 64-bit editions",
			"Microsoft Office 2013 RT Service Pack 1",
			"Microsoft Office 2013 Service Pack 1 (32-bit editions)",
			"Microsoft Office 2013 Service Pack 1 (64-bit editions)",
			"Microsoft Office 2016 (32-bit edition)",
			"Microsoft Office 2016 (64-bit edition)",
			"Microsoft Office 2019 for 32-bit editions",
			"Microsoft Office 2019 for 64-bit editions",
			"Microsoft Office LTSC 2021 for 32-bit editions",
			"Microsoft Office LTSC 2021 for 64-bit editions",
			"Microsoft Office LTSC 2024 for 32-bit editions",
			"Microsoft Office LTSC 2024 for 64-bit editions",
			"Microsoft Office Online Server",
			"Microsoft Office Web Apps Server 2013 Service Pack 1",
			"Microsoft Outlook 2013 (32-bit editions)",
			"Microsoft Outlook 2013 (64-bit editions)",
			"Microsoft Outlook 2013 RT Service Pack 1",
			"Microsoft Outlook 2013 Service Pack 1 (32-bit editions)",
			"Microsoft Outlook 2013 Service Pack 1 (64-bit editions)",
			"Microsoft Outlook 2016 (32-bit edition)",
			"Microsoft Outlook 2016 (64-bit edition)",
			"Microsoft PowerPoint 2013 RT Service Pack 1",
			"Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions)",
			"Microsoft PowerPoint 2013 Service Pack 1 (64-bit editions)",
			"Microsoft PowerPoint 2016 (32-bit edition)",
			"Microsoft PowerPoint 2016 (64-bit edition)",
			"Microsoft Word 2013 RT Service Pack 1",
			"Microsoft Word 2013 Service Pack 1 (32-bit editions)",
			"Microsoft Word 2013 Service Pack 1 (64-bit editions)",
			"Microsoft Word 2016 (32-bit edition)",
			"Microsoft Word 2016 (64-bit edition)",
			"Office Online Server":
			if _, err := officewindowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "officewindowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftOfficeWindows, nil

		// Microsoft SharePoint
		case "Microsoft SharePoint Enterprise Server 2013 Service Pack 1",
			"Microsoft SharePoint Enterprise Server 2016",
			"Microsoft SharePoint Foundation 2013 Service Pack 1",
			"Microsoft SharePoint Server 2013 Service Pack 1",
			"Microsoft SharePoint Server 2016",
			"Microsoft SharePoint Server 2019",
			"Microsoft SharePoint Server Subscription Edition",
			"SharePoint Server Subscription Edition Language Pack":
			if _, err := sharepointversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "sharepointversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftSharePoint, nil

		// Microsoft SQL Server
		case "Microsoft SQL Server 2008 R2 for 32-Bit Systems Service Pack 3 (QFE)",
			"Microsoft SQL Server 2008 R2 for x64-based Systems Service Pack 3 (QFE)",
			"Microsoft SQL Server 2008 for 32-bit Systems Service Pack 4 (QFE)",
			"Microsoft SQL Server 2008 for x64-based Systems Service Pack 4 (QFE)",
			"Microsoft SQL Server 2012 for 32-bit Systems Service Pack 4 (QFE)",
			"Microsoft SQL Server 2012 for x64-based Systems Service Pack 4 (QFE)",
			"Microsoft SQL Server 2014 Service Pack 3 for 32-bit Systems (CU 4)",
			"Microsoft SQL Server 2014 Service Pack 3 for 32-bit Systems (GDR)",
			"Microsoft SQL Server 2014 Service Pack 3 for x64-based Systems (CU 4)",
			"Microsoft SQL Server 2014 Service Pack 3 for x64-based Systems (GDR)",
			"Microsoft SQL Server 2016 for x64-based Systems Service Pack 2 (CU 17)",
			"Microsoft SQL Server 2016 for x64-based Systems Service Pack 2 (GDR)",
			"Microsoft SQL Server 2016 for x64-based Systems Service Pack 3 (GDR)",
			"Microsoft SQL Server 2016 for x64-based Systems Service Pack 3 Azure Connect Feature Pack",
			"Microsoft SQL Server 2017 for x64-based Systems (CU 29)",
			"Microsoft SQL Server 2017 for x64-based Systems (CU 31)",
			"Microsoft SQL Server 2017 for x64-based Systems (GDR)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 16)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 18)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 21)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 22)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 25)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 27)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 28)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 29)",
			"Microsoft SQL Server 2019 for x64-based Systems (CU 32)",
			"Microsoft SQL Server 2019 for x64-based Systems (GDR)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 10)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 12)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 13)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 14)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 15)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 19)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 20)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 21)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 22)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 23)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 5)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 8)",
			"Microsoft SQL Server 2022 for x64-based Systems (GDR)",
			"Microsoft SQL Server 2025 for x64-based Systems (CU2)",
			"Microsoft SQL Server 2025 for x64-based Systems (GDR)",
			"SQL Server 2019 for Linux Containers",
			"SQL Server Integration Services for Visual Studio 2019",
			"SQL Server Integration Services for Visual Studio 2022",
			"SQL Server Management Studio 20.2":
			if _, err := sqlserverversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "sqlserverversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftSQLServer, nil

		// Microsoft Teams for Android
		case "Microsoft Teams for Android":
			if _, err := teamsandroidversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "teamsandroidversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftTeamsAndroid, nil

		// Microsoft Teams (client)
		case "Microsoft Teams":
			if _, err := teamsclientversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "teamsclientversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftTeamsClient, nil

		// Microsoft Teams for Desktop
		case "Microsoft Teams for Desktop":
			if _, err := teamsdesktopversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "teamsdesktopversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftTeamsDesktop, nil

		// Microsoft Teams for iOS
		case "Microsoft Teams for iOS":
			if _, err := teamsiosversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "teamsiosversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftTeamsIOS, nil

		// Microsoft Teams for Mac
		case "Microsoft Teams for Mac":
			if _, err := teamsmacversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "teamsmacversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftTeamsMac, nil

		// Microsoft Visual Studio
		case "Microsoft Visual Studio 2012 Update 5",
			"Microsoft Visual Studio 2013 Update 5",
			"Microsoft Visual Studio 2015 Update 3",
			"Microsoft Visual Studio 2017 Version 15.9 (includes 15.0 - 15.8)",
			"Microsoft Visual Studio 2019 Version 16.10 (includes 16.0 - 16.9)",
			"Microsoft Visual Studio 2019 Version 16.11 (includes 16.0 - 16.10)",
			"Microsoft Visual Studio 2019 Version 16.4 (includes 16.0 - 16.3)",
			"Microsoft Visual Studio 2019 Version 16.7 (includes 16.0 \u2013 16.6)",
			"Microsoft Visual Studio 2019 Version 16.9 (includes 16.0 - 16.8)",
			"Microsoft Visual Studio 2022 Version 17.0",
			"Microsoft Visual Studio 2022 Version 17.1",
			"Microsoft Visual Studio 2022 Version 17.10",
			"Microsoft Visual Studio 2022 Version 17.11",
			"Microsoft Visual Studio 2022 Version 17.12",
			"Microsoft Visual Studio 2022 Version 17.13",
			"Microsoft Visual Studio 2022 Version 17.14",
			"Microsoft Visual Studio 2022 Version 17.2",
			"Microsoft Visual Studio 2022 Version 17.3",
			"Microsoft Visual Studio 2022 Version 17.4",
			"Microsoft Visual Studio 2022 Version 17.5",
			"Microsoft Visual Studio 2022 Version 17.6",
			"Microsoft Visual Studio 2022 Version 17.7",
			"Microsoft Visual Studio 2022 Version 17.8",
			"Microsoft Visual Studio 2022 Version 17.9",
			"Microsoft Visual Studio 2026 Version 18.3":
			if _, err := visualstudioversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "visualstudioversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftVisualStudio, nil

		// Visual Studio Code
		case "Visual Studio Code",
			"Visual Studio Code for Linux":
			if _, err := vscodeversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "vscodeversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftVSCode, nil

		// Windows
		case "Windows 10 for 32-bit Systems",
			"Windows 10 for x64-based Systems",
			"Windows 10 HLK Version 20H2",
			"Windows 10 HLK Version 21H1",
			"Windows 10 HLK Version 21H2",
			"Windows 10 HLK Version 22H2",
			"Windows 10 Version 1511 for 32-bit Systems",
			"Windows 10 Version 1511 for x64-based Systems",
			"Windows 10 Version 1607 for 32-bit Systems",
			"Windows 10 Version 1607 for HoloLens",
			"Windows 10 Version 1607 for x64-based Systems",
			"Windows 10 Version 1703 for 32-bit Systems",
			"Windows 10 Version 1703 for x64-based Systems",
			"Windows 10 Version 1709 for 32-bit Systems",
			"Windows 10 Version 1709 for ARM64-based Systems",
			"Windows 10 Version 1709 for x64-based Systems",
			"Windows 10 Version 1803 for 32-bit Systems",
			"Windows 10 Version 1803 for ARM64-based Systems",
			"Windows 10 Version 1803 for x64-based Systems",
			"Windows 10 Version 1809 for 32-bit Systems",
			"Windows 10 Version 1809 for ARM64-based Systems",
			"Windows 10 Version 1809 for HoloLens",
			"Windows 10 Version 1809 for x64-based Systems",
			"Windows 10 Version 1903 for 32-bit Systems",
			"Windows 10 Version 1903 for ARM64-based Systems",
			"Windows 10 Version 1903 for HoloLens",
			"Windows 10 Version 1903 for x64-based Systems",
			"Windows 10 Version 1909 for 32-bit Systems",
			"Windows 10 Version 1909 for ARM64-based Systems",
			"Windows 10 Version 1909 for x64-based Systems",
			"Windows 10 Version 2004 for 32-bit Systems",
			"Windows 10 Version 2004 for ARM64-based Systems",
			"Windows 10 Version 2004 for HoloLens",
			"Windows 10 Version 2004 for x64-based Systems",
			"Windows 10 Version 20H2 for 32-bit Systems",
			"Windows 10 Version 20H2 for ARM64-based Systems",
			"Windows 10 Version 20H2 for x64-based Systems",
			"Windows 10 Version 21H1 for 32-bit Systems",
			"Windows 10 Version 21H1 for ARM64-based Systems",
			"Windows 10 Version 21H1 for x64-based Systems",
			"Windows 10 Version 21H2 for 32-bit Systems",
			"Windows 10 Version 21H2 for ARM64-based Systems",
			"Windows 10 Version 21H2 for x64-based Systems",
			"Windows 10 Version 22H2 for 32-bit Systems",
			"Windows 10 Version 22H2 for ARM64-based Systems",
			"Windows 10 Version 22H2 for x64-based Systems",
			"Windows 11 HLK 22H2",
			"Windows 11 HLK 23H2",
			"Windows 11 HLK 24H2",
			"Windows 11 Version 21H2 for ARM64-based Systems",
			"Windows 11 Version 21H2 for x64-based Systems",
			"Windows 11 Version 22H2 for ARM64-based Systems",
			"Windows 11 Version 22H2 for x64-based Systems",
			"Windows 11 Version 23H2 for ARM64-based Systems",
			"Windows 11 Version 23H2 for x64-based Systems",
			"Windows 11 Version 24H2 for ARM64-based Systems",
			"Windows 11 Version 24H2 for x64-based Systems",
			"Windows 11 Version 25H2 for ARM64-based Systems",
			"Windows 11 Version 25H2 for x64-based Systems",
			"Windows 11 Version 26H1 for ARM64-based Systems",
			"Windows 11 Version 26H1 for x64-based Systems",
			"Windows 7 for 32-bit Systems Service Pack 1",
			"Windows 7 for x64-based Systems Service Pack 1",
			"Windows 8.1 for 32-bit Systems",
			"Windows 8.1 for x64-based Systems",
			"Windows RT 8.1",
			"Windows Server 2008 for 32-bit Systems (Server Core installation)",
			"Windows Server 2008 for 32-bit Systems Service Pack 2",
			"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)",
			"Windows Server 2008 for Itanium-based Systems Service Pack 2",
			"Windows Server 2008 for x64-based Systems (Server Core installation)",
			"Windows Server 2008 for x64-based Systems Service Pack 2",
			"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)",
			"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1",
			"Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)",
			"Windows Server 2012",
			"Windows Server 2012 (Server Core installation)",
			"Windows Server 2012 R2",
			"Windows Server 2012 R2 (Server Core installation)",
			"Windows Server 2016",
			"Windows Server 2016 (Server Core installation)",
			"Windows Server 2019",
			"Windows Server 2019 (Server Core installation)",
			"Windows Server 2022",
			"Windows Server 2022 (Server Core installation)",
			"Windows Server 2022, 23H2 Edition (Server Core installation)",
			"Windows Server 2025",
			"Windows Server 2025 (Server Core installation)",
			"Windows Server, Version 1909 (Server Core installation)",
			"Windows Server, Version 1709 (Server Core installation)",
			"Windows Server, Version 1803 (Server Core installation)",
			"Windows Server, Version 1903 (Server Core installation)",
			"Windows Server, Version 2004 (Server Core installation)",
			"Windows Server, Version 20H2 (Server Core installation)":
			if _, err := windowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "windowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftWindows, nil

		// Internet Explorer (FixedBuild is the Windows OS build number, not an IE-specific version)
		case "Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 1803 for ARM64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1809 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 1809 for ARM64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1809 for x64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1909 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 1909 for ARM64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 1909 for x64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 2004 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 2004 for ARM64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 2004 for x64-based Systems",
			"Internet Explorer 11 on Windows 10 Version 20H2 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 Version 20H2 for ARM64-based Systems",
			"Internet Explorer 11 on Windows 10 for 32-bit Systems",
			"Internet Explorer 11 on Windows 10 for x64-based Systems",
			"Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1",
			"Internet Explorer 11 on Windows 7 for x64-based Systems Service Pack 1",
			"Internet Explorer 11 on Windows 8.1 for 32-bit Systems",
			"Internet Explorer 11 on Windows 8.1 for x64-based Systems",
			"Internet Explorer 11 on Windows RT 8.1",
			"Internet Explorer 11 on Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			"Internet Explorer 11 on Windows Server 2012",
			"Internet Explorer 11 on Windows Server 2012 R2",
			"Internet Explorer 11 on Windows Server 2016",
			"Internet Explorer 11 on Windows Server 2019",
			"Internet Explorer 9 on Windows Server 2008 for 32-bit Systems Service Pack 2",
			"Internet Explorer 9 on Windows Server 2008 for x64-based Systems Service Pack 2":
			if _, err := windowsversion.NewVersion(fixedBuild); err != nil {
				return rangeTypes.RangeTypeUnknown, errors.Wrap(err, "windowsversion.NewVersion")
			}
			return rangeTypes.RangeTypeMicrosoftWindows, nil

		// Products that match detection prefixes but don't need FixedBuild validation.
		// These are tools, extensions, mobile apps, or products whose FixedBuild format
		// doesn't match the category's version parser.
		case ".NET Education Bundle SDK Install Tool",
			".NET Install Tool for Extension Authors",
			"Microsoft Edge (Chromium-based) Updater",
			"Microsoft Office Deployment Tool",
			"Microsoft Office for Android",
			"Microsoft Office for Universal",
			"Microsoft Office for iOS",
			"Microsoft Outlook 2016 for Mac",
			"SQL Server backend for Django",
			"Teams Panels",
			"Teams Phones",
			"Teams for D365 Guides Hololens",
			"Teams for D365 Remote Assist HoloLens",
			"Visual Studio Code - GitHub Pull Requests and Issues Extension",
			"Visual Studio Code - JS Debug Extension",
			"Visual Studio Code - Kubernetes Tools",
			"Visual Studio Code Remote - Containers Extension",
			"Visual Studio Code Remote - SSH Extension",
			"Visual Studio Code WSL Extension":
			return rangeTypes.RangeTypeUnknown, nil

		default:
			// Detect new products that likely need validation but aren't explicitly listed above.
			for _, prefix := range []string{
				".NET ",
				"Microsoft Defender ",
				"Windows Defender ",
				"Microsoft Edge (Chromium-based)",
				"Microsoft Exchange Server",
				"Microsoft Office ",
				"Office Online Server",
				"Microsoft Excel 20",
				"Microsoft Outlook 20",
				"Microsoft PowerPoint 20",
				"Microsoft Word 20",
				"Microsoft SharePoint",
				"SharePoint ",
				"Microsoft SQL Server 20",
				"SQL Server ",
				"Microsoft Teams ",
				"Teams ",
				"Microsoft Visual Studio 20",
				"Visual Studio Code",
				"Internet Explorer ",
				"Windows 7 ",
				"Windows 8",
				"Windows 10 ",
				"Windows 11 ",
				"Windows Server ",
				"Windows Server,",
				"Windows RT ",
			} {
				if strings.HasPrefix(productName, prefix) {
					return rangeTypes.RangeTypeUnknown, errors.Errorf("unknown product %q (matches prefix %q) not listed in buildFixedBuildCriterion, please add it", productName, prefix)
				}
			}
			return rangeTypes.RangeTypeUnknown, nil
		}
	}()
	if err != nil {
		return nil, errors.Wrapf(err, "unexpected FixedBuild format for %s (%s): %q", cveID, productName, fixedBuild)
	}
	if rt == rangeTypes.RangeTypeUnknown {
		return nil, nil
	}

	return &criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeVersion,
		Version: &vcTypes.Criterion{
			Vulnerable: true,
			FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
			Package: criterionpackageTypes.Package{
				Type:   criterionpackageTypes.PackageTypeBinary,
				Binary: &binaryTypes.Package{Name: productName},
			},
			Affected: &affectedTypes.Affected{
				Type:  rt,
				Range: []rangeTypes.Range{{LessThan: fixedBuild}},
				Fixed: []string{fixedBuild},
			},
		},
	}, nil
}

// fixedBuildOverrides maps (CVE ID, product name, incorrect FixedBuild) to corrected FixedBuild values
// for known data issues in CVRF.
// The key is [3]string{CVE ID, raw product name, incorrect FixedBuild value after generic cleanup}.
var fixedBuildOverrides = map[[3]string]string{
	// .NET Core / .NET 5+ (FixedBuild has pre-release suffix that the parser doesn't accept)
	// 2021-May (FixedBuild "5.0.6-servicing.21220.11" / "3.1.15-servicing.21214.3" has pre-release suffix)
	{"CVE-2021-31204", ".NET 5.0", "5.0.6-servicing.21220.11"}:      "5.0.6",
	{"CVE-2021-31204", ".NET Core 3.1", "3.1.15-servicing.21214.3"}: "3.1.15",

	// Microsoft Defender for Endpoint for Linux (FixedBuild "1.0.9.0" is 4-part, parser expects 3-part)
	{"CVE-2026-21537", "Microsoft Defender for Endpoint for Linux", "1.0.9.0"}: "1.0.9",

	// Microsoft Edge (Chromium-based)
	// 2020-May (Edge 83)
	{"CVE-2020-1195", "Microsoft Edge (Chromium-based)", ""}: "83.0.478.37",
	// 2020-Jul (Edge 84)
	{"CVE-2020-1341", "Microsoft Edge (Chromium-based)", ""}: "84.0.522.40",
	// 2020-Sep (Edge 85)
	{"CVE-2020-16884", "Microsoft Edge (Chromium-based)", ""}: "85.0.564.44",
	// 2021-Jan (Edge 88.0.705.50)
	{"CVE-2020-16044", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21118", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21119", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21120", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21121", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21122", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21123", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21124", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21125", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21126", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21127", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21128", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21129", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21130", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21131", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21132", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21133", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21134", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21135", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21136", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21137", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21139", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21140", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	{"CVE-2021-21141", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.50",
	// 2021-Feb (Edge 88.0.705.62, 88.0.705.63, 88.0.705.74)
	{"CVE-2021-21142", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21143", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21144", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21145", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21146", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21147", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-24113", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.62",
	{"CVE-2021-21148", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.63",
	{"CVE-2021-21149", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21150", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21151", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21152", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21153", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21154", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21155", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21156", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	{"CVE-2021-21157", "Microsoft Edge (Chromium-based)", ""}: "88.0.705.74",
	// 2021-Mar (Edge 89.0.774.45, 89.0.774.54)
	{"CVE-2020-27844", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21159", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21160", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21161", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21162", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21163", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21164", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21165", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21166", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21167", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21168", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21169", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21170", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21171", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21172", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21173", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21174", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21175", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21176", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21177", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21178", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21179", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21180", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21181", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21182", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21183", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21184", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21185", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21186", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21187", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21188", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21189", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21190", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.45",
	{"CVE-2021-21191", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.54",
	{"CVE-2021-21192", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.54",
	{"CVE-2021-21193", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.54",
	// 2021-Apr (Edge 89.0.774.68, 89.0.774.77, 90.0.818.39, 90.0.818.46, 90.0.818.51)
	{"CVE-2021-21194", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21195", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21196", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21197", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21198", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21199", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.68",
	{"CVE-2021-21206", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.77",
	{"CVE-2021-21220", "Microsoft Edge (Chromium-based)", ""}: "89.0.774.77",
	{"CVE-2021-21201", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21202", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21203", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21204", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21205", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21207", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21208", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21209", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21210", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21211", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21212", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21213", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21214", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21215", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21216", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21217", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21218", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21219", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21221", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.39",
	{"CVE-2021-21222", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.46",
	{"CVE-2021-21223", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.46",
	{"CVE-2021-21224", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.46",
	{"CVE-2021-21225", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.46",
	{"CVE-2021-21226", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.46",
	{"CVE-2021-21227", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21228", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21229", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21230", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21231", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21232", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	{"CVE-2021-21233", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.51",
	// 2021-May (Edge 90.0.818.62)
	{"CVE-2021-30506", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30507", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30508", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30509", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30510", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30511", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30512", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30513", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30514", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30515", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30516", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30517", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30518", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30519", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	{"CVE-2021-30520", "Microsoft Edge (Chromium-based)", ""}: "90.0.818.62",
	// 2021-Jun (Edge 91.0.864.48)
	{"CVE-2021-30544", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30545", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30546", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30547", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30548", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30549", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30550", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30551", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30552", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	{"CVE-2021-30553", "Microsoft Edge (Chromium-based)", ""}: "91.0.864.48",
	// 2021-Nov (Edge 96.0.1954.29, FixedBuild has typo "96.0 1954.29")
	{"CVE-2021-38005", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38006", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38007", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38008", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38009", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38010", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38011", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38012", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38013", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38014", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38015", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38016", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38017", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38018", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38019", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38020", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38021", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-38022", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-42308", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-43220", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	{"CVE-2021-43221", "Microsoft Edge (Chromium-based)", "96.0 1954.29"}: "96.0.1954.29",
	// 2023-Feb (Edge 109.0.1518.78, FixedBuild has typo "109.0.15.18.78")
	{"CVE-2023-21720", "Microsoft Edge (Chromium-based)", "109.0.15.18.78"}: "109.0.1518.78",
	// 2023-Apr (Edge 112.0.1722.34, FixedBuild has Chromium version "112.0.5615.49/50" instead of Edge version)
	{"CVE-2023-1810", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1811", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1812", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1813", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1814", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1815", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1816", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1817", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1818", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1819", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1820", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1821", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1822", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-1823", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}:  "112.0.1722.34",
	{"CVE-2023-24935", "Microsoft Edge (Chromium-based)", "112.0.5615.49/50"}: "112.0.1722.34",
	// 2025-May (Edge 136.0.3240.64, FixedBuild has "v" prefix "v136.0.3240.64")
	{"CVE-2025-4372", "Microsoft Edge (Chromium-based)", "v136.0.3240.64"}: "136.0.3240.64",
	// 2026-Mar (Edge 145.0.3800.99, FixedBuild "145.3800.99" has only 3 segments instead of 4)
	{"CVE-2026-3537", "Microsoft Edge (Chromium-based)", "145.3800.99"}: "145.0.3800.99",

	// Microsoft Office / Excel / Office Online Server / Office Web Apps Server
	// 2021-Sep (FixedBuild "5381.1000" / "5215.1000" / "10378.20000" missing "15.0." or "16.0." prefix)
	{"CVE-2021-38646", "Microsoft Office 2013 RT Service Pack 1", "5381.1000"}:                "15.0.5381.1000",
	{"CVE-2021-38646", "Microsoft Office 2013 Service Pack 1 (32-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38646", "Microsoft Office 2013 Service Pack 1 (64-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38650", "Microsoft Office 2013 RT Service Pack 1", "5381.1000"}:                "15.0.5381.1000",
	{"CVE-2021-38650", "Microsoft Office 2013 Service Pack 1 (32-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38650", "Microsoft Office 2013 Service Pack 1 (64-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38658", "Microsoft Office 2013 RT Service Pack 1", "5381.1000"}:                "15.0.5381.1000",
	{"CVE-2021-38658", "Microsoft Office 2013 Service Pack 1 (32-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38658", "Microsoft Office 2013 Service Pack 1 (64-bit editions)", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38658", "Microsoft Office 2016 (32-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38658", "Microsoft Office 2016 (64-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38646", "Microsoft Office 2016 (32-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38646", "Microsoft Office 2016 (64-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38650", "Microsoft Office 2016 (32-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38650", "Microsoft Office 2016 (64-bit edition)", "5215.1000"}:                 "16.0.5215.1000",
	{"CVE-2021-38655", "Microsoft Excel 2013 RT Service Pack 1", "5381.1000"}:                 "15.0.5381.1000",
	{"CVE-2021-38655", "Microsoft Excel 2013 Service Pack 1 (32-bit editions)", "5381.1000"}:  "15.0.5381.1000",
	{"CVE-2021-38655", "Microsoft Excel 2013 Service Pack 1 (64-bit editions)", "5381.1000"}:  "15.0.5381.1000",
	{"CVE-2021-38660", "Microsoft Excel 2013 RT Service Pack 1", "5381.1000"}:                 "15.0.5381.1000",
	{"CVE-2021-38660", "Microsoft Excel 2013 Service Pack 1 (32-bit editions)", "5381.1000"}:  "15.0.5381.1000",
	{"CVE-2021-38660", "Microsoft Excel 2013 Service Pack 1 (64-bit editions)", "5381.1000"}:  "15.0.5381.1000",
	{"CVE-2021-38655", "Microsoft Excel 2016 (32-bit edition)", "5215.1000"}:                  "16.0.5215.1000",
	{"CVE-2021-38655", "Microsoft Excel 2016 (64-bit edition)", "5215.1000"}:                  "16.0.5215.1000",
	{"CVE-2021-38655", "Microsoft Office Online Server", "10378.20000"}:                       "16.0.10378.20000",
	{"CVE-2021-38655", "Microsoft Office Web Apps Server 2013 Service Pack 1", "5381.1000"}:   "15.0.5381.1000",
	// 2021-Jul (Office 2019 for Mac, FixedBuild "16.51.210711.01" has extra dot in build segment, should be "16.51.21071101")
	{"CVE-2021-34501", "Microsoft Office 2019 for Mac", "16.51.210711.01"}: "16.51.21071101",

	// Microsoft SharePoint
	// 2021-Sep (FixedBuild "5381.1000" / "5215.1000" / "10378.20002" missing "15.0." or "16.0." prefix)
	{"CVE-2021-38651", "Microsoft SharePoint Foundation 2013 Service Pack 1", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38652", "Microsoft SharePoint Foundation 2013 Service Pack 1", "5381.1000"}: "15.0.5381.1000",
	{"CVE-2021-38651", "Microsoft SharePoint Enterprise Server 2016", "5215.1000"}:         "16.0.5215.1000",
	{"CVE-2021-38652", "Microsoft SharePoint Enterprise Server 2016", "5215.1000"}:         "16.0.5215.1000",
	{"CVE-2021-38651", "Microsoft SharePoint Server 2019", "10378.20002"}:                  "16.0.10378.20002",
	// 2022-Dec (FixedBuild "10393.20000" / "15601.20316" missing "16.0." prefix)
	{"CVE-2022-44690", "Microsoft SharePoint Server 2019", "10393.20000"}:                 "16.0.10393.20000",
	{"CVE-2022-44693", "Microsoft SharePoint Server 2019", "10393.20000"}:                 "16.0.10393.20000",
	{"CVE-2022-44690", "Microsoft SharePoint Server Subscription Edition", "15601.20316"}: "16.0.15601.20316",
	{"CVE-2022-44693", "Microsoft SharePoint Server Subscription Edition", "15601.20316"}: "16.0.15601.20316",

	// Microsoft Teams for Android (FixedBuild "1416/..." has numeric prefix before slash)
	{"CVE-2022-21965", "Microsoft Teams for Android", "1416/1.0.0.2021040701"}: "1.0.0.2021040701",
	{"CVE-2025-53783", "Microsoft Teams for Android", "1416/1.0.0.2025102802"}: "1.0.0.2025102802",

	// Teams Panels / Phones (FixedBuild "1449/..." has numeric prefix before slash)
	{"CVE-2025-53783", "Teams Panels", "1449/1.0.97.2025102203"}: "1.0.97.2025102203",
	{"CVE-2025-53783", "Teams Phones", "1449/1.0.94.2025168802"}: "1.0.94.2025168802",

	// Microsoft Teams for iOS (FixedBuild has trailing parenthetical build ID)
	{"CVE-2025-49731", "Microsoft Teams for iOS", "7.10.1 (100772025102901)"}: "7.10.1",
	{"CVE-2025-53783", "Microsoft Teams for iOS", "7.10.1 (100772025102901)"}: "7.10.1",

	// Microsoft Visual Studio
	// 2021-Nov (VS 2015 Update 3 14.0.27550.0, FixedBuild "27550.00" missing "14.0." prefix)
	{"CVE-2021-42277", "Microsoft Visual Studio 2015 Update 3", "27550.00"}: "14.0.27550.0",
	// 2022-Jan (VS 2015 Update 3 14.0.27551.0, FixedBuild "27551.00" missing "14.0." prefix)
	{"CVE-2022-21871", "Microsoft Visual Studio 2015 Update 3", "27551.00"}: "14.0.27551.0",

	// Visual Studio Code
	// 2021-May (VS Code 1.56.0, FixedBuild "1.56" missing ".0" suffix)
	{"CVE-2021-31211", "Visual Studio Code", "1.56"}: "1.56.0",
	{"CVE-2021-31214", "Visual Studio Code", "1.56"}: "1.56.0",
	// 2021-Jul (VS Code 1.58.0, FixedBuild "1.58" missing ".0" suffix)
	{"CVE-2021-34479", "Visual Studio Code", "1.58"}: "1.58.0",
	{"CVE-2021-34528", "Visual Studio Code", "1.58"}: "1.58.0",
	// 2023-Jun (VS Code 1.79.0, FixedBuild "1.79" missing ".0" suffix)
	{"CVE-2023-33144", "Visual Studio Code", "1.79"}: "1.79.0",

	// Windows / Internet Explorer
	// 2023-May (FixedBuild "0.0.26200.4652" is a typo for "10.0.26100.4652" — the ARM64 entry has the correct value)
	{"CVE-2023-24932", "Windows 11 Version 24H2 for x64-based Systems", "0.0.26200.4652"}: "10.0.26100.4652",
	// 2021-Jun (IE Cumulative, FixedBuild "1.0.0.0" is a revision number, not a Windows OS build)
	{"CVE-2021-31959", "Windows 8.1 for 32-bit Systems", "1.0.0.0"}:    "",
	{"CVE-2021-31959", "Windows 8.1 for x64-based Systems", "1.0.0.0"}: "",
	{"CVE-2021-31959", "Windows Server 2012", "1.0.0.0"}:               "",
	{"CVE-2021-31959", "Windows Server 2012 R2", "1.0.0.0"}:            "",
	{"CVE-2021-31971", "Windows 8.1 for 32-bit Systems", "1.0.0.0"}:    "",
	{"CVE-2021-31971", "Windows 8.1 for x64-based Systems", "1.0.0.0"}: "",
	{"CVE-2021-31971", "Windows Server 2012", "1.0.0.0"}:               "",
	{"CVE-2021-31971", "Windows Server 2012 R2", "1.0.0.0"}:            "",
	{"CVE-2021-33742", "Windows 8.1 for 32-bit Systems", "1.0.0.0"}:    "",
	{"CVE-2021-33742", "Windows 8.1 for x64-based Systems", "1.0.0.0"}: "",
	{"CVE-2021-33742", "Windows Server 2012", "1.0.0.0"}:               "",
	{"CVE-2021-33742", "Windows Server 2012 R2", "1.0.0.0"}:            "",
	// 2025-Mar (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2025-21247", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-21247", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-21247", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-21247", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-21247", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-21247", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	// 2025-Apr (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2025-27737", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-27737", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-27737", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-27737", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-27737", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-27737", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-27737", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-27737", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-27737", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-27737", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	// 2025-Jun (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2025-33053", "Windows Server 2012", "1.000"}:                            "",
	{"CVE-2025-33053", "Windows Server 2012 (Server Core installation)", "1.000"}: "",
	// 2025-Sep (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2025-54107", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-54107", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-54107", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-54107", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-54107", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-54107", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-54107", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-54107", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-54107", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-54107", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	{"CVE-2025-54917", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-54917", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-54917", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-54917", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-54917", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-54917", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-54917", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-54917", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-54917", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-54917", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	// 2025-Oct (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2025-58739", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-58739", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-58739", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-58739", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-58739", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-58739", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-58739", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-58739", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-58739", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-58739", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	{"CVE-2025-59208", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-59208", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-59208", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-59208", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-59208", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-59208", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-59208", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-59208", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-59208", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-59208", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	{"CVE-2025-59295", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.000"}:                            "",
	{"CVE-2025-59295", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.000"}: "",
	{"CVE-2025-59295", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.000"}:                                  "",
	{"CVE-2025-59295", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.000"}:       "",
	{"CVE-2025-59295", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.000"}:                               "",
	{"CVE-2025-59295", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.000"}:    "",
	{"CVE-2025-59295", "Windows Server 2012", "1.000"}:                                                                    "",
	{"CVE-2025-59295", "Windows Server 2012 (Server Core installation)", "1.000"}:                                         "",
	{"CVE-2025-59295", "Windows Server 2012 R2", "1.000"}:                                                                 "",
	{"CVE-2025-59295", "Windows Server 2012 R2 (Server Core installation)", "1.000"}:                                      "",
	// 2026-Mar (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2026-23674", "Windows Server 2012", "1.000"}:                               "",
	{"CVE-2026-23674", "Windows Server 2012 (Server Core installation)", "1.000"}:    "",
	{"CVE-2026-23674", "Windows Server 2012 R2", "1.000"}:                            "",
	{"CVE-2026-23674", "Windows Server 2012 R2 (Server Core installation)", "1.000"}: "",
	// 2021-Oct (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2021-41342", "Windows 7 for 32-bit Systems Service Pack 1", "1.001"}:                 "",
	{"CVE-2021-41342", "Windows 7 for x64-based Systems Service Pack 1", "1.001"}:              "",
	{"CVE-2021-41342", "Windows 8.1 for 32-bit Systems", "1.001"}:                              "",
	{"CVE-2021-41342", "Windows 8.1 for x64-based Systems", "1.001"}:                           "",
	{"CVE-2021-41342", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}: "",
	{"CVE-2021-41342", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.001"}:       "",
	{"CVE-2021-41342", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.001"}:    "",
	{"CVE-2021-41342", "Windows Server 2012", "1.001"}:                                         "",
	{"CVE-2021-41342", "Windows Server 2012 R2", "1.001"}:                                      "",
	// 2023-Jul (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2023-32046", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2023-32046", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2023-32046", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.001"}:                                  "",
	{"CVE-2023-32046", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.001"}:       "",
	{"CVE-2023-32046", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.001"}:                               "",
	{"CVE-2023-32046", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.001"}:    "",
	{"CVE-2023-32046", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2023-32046", "Windows Server 2012 (Server Core installation)", "1.001"}:                                         "",
	{"CVE-2023-32046", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2023-32046", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	{"CVE-2023-35308", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2023-35308", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	{"CVE-2023-35336", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2023-35336", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2023-Sep (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2023-36805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2023-36805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2023-36805", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2023-36805", "Windows Server 2012 (Server Core installation)", "1.001"}:                                         "",
	{"CVE-2023-36805", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2023-36805", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2023-Oct (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2023-36436", "Windows Server 2012", "1.001"}:                               "",
	{"CVE-2023-36436", "Windows Server 2012 (Server Core installation)", "1.001"}:    "",
	{"CVE-2023-36436", "Windows Server 2012 R2", "1.001"}:                            "",
	{"CVE-2023-36436", "Windows Server 2012 R2 (Server Core installation)", "1.001"}: "",
	// 2023-Nov (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2023-36017", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2023-36017", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2023-36017", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2023-36017", "Windows Server 2012 (Server Core installation)", "1.001"}:                                         "",
	{"CVE-2023-36017", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2023-36017", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2023-Dec (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2023-35628", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2023-35628", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2023-35628", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2023-35628", "Windows Server 2012 (Server Core installation)", "1.001"}:                                         "",
	{"CVE-2023-35628", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2024-Jan (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2024-20652", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2024-20652", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2024-20652", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2024-20652", "Windows Server 2012 (Server Core installation)", "1.001"}:                                         "",
	{"CVE-2024-20652", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2024-20652", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2024-Jul (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2024-38112", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.001"}:                               "",
	{"CVE-2024-38112", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.001"}:    "",
	{"CVE-2024-38112", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.001"}:                            "",
	{"CVE-2024-38112", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.001"}: "",
	{"CVE-2024-38112", "Windows Server 2012 R2", "1.001"}:                                                              "",
	{"CVE-2024-38112", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                   "",
	// 2024-Aug (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2024-38178", "Windows Server 2012 R2", "1.001"}:                            "",
	{"CVE-2024-38178", "Windows Server 2012 R2 (Server Core installation)", "1.001"}: "",
	// 2024-Sep (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2024-30073", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2024-30073", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2024-30073", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.001"}:                                  "",
	{"CVE-2024-30073", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.001"}:                               "",
	{"CVE-2024-30073", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2024-30073", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2024-43461", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2024-43461", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2024-43461", "Windows Server 2012", "1.001"}:                                                                    "",
	{"CVE-2024-43461", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	// 2024-Nov (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{"CVE-2024-43451", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.001"}:                            "",
	{"CVE-2024-43451", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.001"}: "",
	{"CVE-2024-43451", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.001"}:                                  "",
	{"CVE-2024-43451", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.001"}:       "",
	{"CVE-2024-43451", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.001"}:                               "",
	{"CVE-2024-43451", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.001"}:    "",
	{"CVE-2024-43451", "Windows Server 2012 R2", "1.001"}:                                                                 "",
	{"CVE-2024-43451", "Windows Server 2012 R2 (Server Core installation)", "1.001"}:                                      "",
	// 2020-Feb (UEFI/Secure Boot firmware or IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2020-0689", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2020-Jul (UEFI/Secure Boot firmware or IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"ADV200011", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"ADV200011", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2022-Aug (UEFI/Secure Boot firmware or IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2022-34301", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34301", "Windows 10 for x64-based Systems", "1.002"}: "",
	{"CVE-2022-34302", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34302", "Windows 10 for x64-based Systems", "1.002"}: "",
	{"CVE-2022-34303", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34303", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2023-Dec (UEFI/Secure Boot firmware or IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2023-35628", "Windows Server 2012 R2", "1.002"}: "",
	// 2025-Jan (UEFI/Secure Boot firmware or IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2025-21189", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21189", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21268", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21268", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21269", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21269", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21276", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21276", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21328", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21328", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21329", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21329", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	{"CVE-2025-21332", "Windows Server 2012 R2", "1.002"}:                            "",
	{"CVE-2025-21332", "Windows Server 2012 R2 (Server Core installation)", "1.002"}: "",
	// 2025-Jan (IE Cumulative, FixedBuild "1.003" is a revision number, not a Windows OS build)
	{"CVE-2025-21189", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21189", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21189", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21189", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21268", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21268", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21268", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21268", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21269", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21269", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21269", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21269", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21276", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21276", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21276", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21276", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21328", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21328", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21328", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21328", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21329", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21329", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21329", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21329", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-21332", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-21332", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-21332", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-21332", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	// 2025-May (IE Cumulative, FixedBuild "1.003" is a revision number, not a Windows OS build)
	{"CVE-2025-30397", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.003"}:                            "",
	{"CVE-2025-30397", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.003"}: "",
	{"CVE-2025-30397", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.003"}:                                  "",
	{"CVE-2025-30397", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.003"}:       "",
	{"CVE-2025-30397", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.003"}:                               "",
	{"CVE-2025-30397", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.003"}:    "",
	{"CVE-2025-30397", "Windows Server 2012", "1.003"}:                                                                    "",
	{"CVE-2025-30397", "Windows Server 2012 (Server Core installation)", "1.003"}:                                         "",
	{"CVE-2025-30397", "Windows Server 2012 R2", "1.003"}:                                                                 "",
	{"CVE-2025-30397", "Windows Server 2012 R2 (Server Core installation)", "1.003"}:                                      "",
	// 2025-Jan (IE Cumulative, FixedBuild "1.007" is a revision number, not a Windows OS build)
	{"CVE-2025-21189", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21189", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21189", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21189", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21268", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21268", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21268", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21268", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21269", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21269", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21269", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21269", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21276", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21276", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21276", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21276", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21328", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21328", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21328", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21328", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21329", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21329", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21329", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21329", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	{"CVE-2025-21332", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.007"}:                               "",
	{"CVE-2025-21332", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.007"}:    "",
	{"CVE-2025-21332", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.007"}:                            "",
	{"CVE-2025-21332", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.007"}: "",
	// 2022-Mar (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{"CVE-2022-24502", "Windows 7 for 32-bit Systems Service Pack 1", "1.1.0.0"}:                 "",
	{"CVE-2022-24502", "Windows 7 for x64-based Systems Service Pack 1", "1.1.0.0"}:              "",
	{"CVE-2022-24502", "Windows 8.1 for 32-bit Systems", "1.1.0.0"}:                              "",
	{"CVE-2022-24502", "Windows 8.1 for x64-based Systems", "1.1.0.0"}:                           "",
	{"CVE-2022-24502", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.1.0.0"}: "",
	{"CVE-2022-24502", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.1.0.0"}:       "",
	{"CVE-2022-24502", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.1.0.0"}:    "",
	{"CVE-2022-24502", "Windows Server 2012", "1.1.0.0"}:                                         "",
	{"CVE-2022-24502", "Windows Server 2012 R2", "1.1.0.0"}:                                      "",
	// 2023-Feb (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{"CVE-2023-21805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.1.0.0"}:                            "",
	{"CVE-2023-21805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.1.0.0"}: "",
	{"CVE-2023-21805", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.1.0.0"}:                                  "",
	{"CVE-2023-21805", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:       "",
	{"CVE-2023-21805", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.1.0.0"}:                               "",
	{"CVE-2023-21805", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:    "",
	{"CVE-2023-21805", "Windows Server 2012", "1.1.0.0"}:                                                                    "",
	{"CVE-2023-21805", "Windows Server 2012 (Server Core installation)", "1.1.0.0"}:                                         "",
	// 2023-May (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{"CVE-2023-29324", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.1.0.0"}:                            "",
	{"CVE-2023-29324", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.1.0.0"}: "",
	{"CVE-2023-29324", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.1.0.0"}:                                  "",
	{"CVE-2023-29324", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:       "",
	{"CVE-2023-29324", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.1.0.0"}:                               "",
	{"CVE-2023-29324", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:    "",
	{"CVE-2023-29324", "Windows Server 2012", "1.1.0.0"}:                                                                    "",
	{"CVE-2023-29324", "Windows Server 2012 (Server Core installation)", "1.1.0.0"}:                                         "",
	{"CVE-2023-29324", "Windows Server 2012 R2", "1.1.0.0"}:                                                                 "",
	{"CVE-2023-29324", "Windows Server 2012 R2 (Server Core installation)", "1.1.0.0"}:                                      "",
	// 2023-Aug (IE Cumulative, FixedBuild "10.0.0.0" is a revision number, not a Windows OS build)
	{"CVE-2023-35384", "Windows Server 2012 R2", "10.0.0.0"}:                            "",
	{"CVE-2023-35384", "Windows Server 2012 R2 (Server Core installation)", "10.0.0.0"}: "",
	// 2021-May (IE Cumulative, FixedBuild "6.0"/"6.1"/"6.2" matches OS major.minor but is a truncated IE revision)
	{"CVE-2021-26419", "Internet Explorer 9 on Windows Server 2008 for 32-bit Systems Service Pack 2", "6.0"}:        "",
	{"CVE-2021-26419", "Internet Explorer 9 on Windows Server 2008 for x64-based Systems Service Pack 2", "6.0"}:     "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1", "6.1"}:                 "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows 7 for x64-based Systems Service Pack 1", "6.1"}:              "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows Server 2008 R2 for x64-based Systems Service Pack 1", "6.1"}: "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows Server 2012", "6.2"}:                                         "",
}

func buildKBCriterion(product, kbID string) *criterionTypes.Criterion {
	if !isAllDigits(kbID) {
		return nil
	}
	return &criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeKB,
		KB:   &kbcTypes.Criterion{Product: product, KBID: kbID},
	}
}

// appendOrMergeSegment adds seg to an existing item whose content matches (determined by compare returning 0),
// or appends newItem if no match is found.

func (e extractor) collectKBs(v cvrf.Vulnerability, products map[string]string, kbm map[string]microsoftkbTypes.KB) error {
	for _, r := range v.Remediations.Remediation {
		if r.Type != "Vendor Fix" {
			continue
		}
		for _, pid := range r.ProductID {
			productName, ok := products[pid]
			if !ok {
				return errors.Errorf("product ID %q not found in product tree for %s", pid, v.CVE)
			}
			if isCBLMarinerOrAzureLinux(productName) {
				continue
			}

			criterionProductName := microsoftutil.NormalizeProductName(productName)

			kbID := r.Description
			if !isAllDigits(kbID) {
				continue
			}

			kb := kbm[kbID]
			if kb.KBID == "" {
				kb.KBID = kbID
				kb.URL = fmt.Sprintf("https://support.microsoft.com/help/%s", kbID)
				kb.DataSource = sourceTypes.Source{
					ID:   sourceTypes.MicrosoftCVRF,
					Raws: e.r.Paths(),
				}
			}
			if !slices.Contains(kb.Products, criterionProductName) {
				kb.Products = append(kb.Products, criterionProductName)
			}
			kbm[kbID] = kb

			if isAllDigits(r.Supercedence) {
				skb := kbm[r.Supercedence]
				if skb.KBID == "" {
					skb.KBID = r.Supercedence
					skb.URL = fmt.Sprintf("https://support.microsoft.com/help/%s", r.Supercedence)
					skb.DataSource = sourceTypes.Source{
						ID:   sourceTypes.MicrosoftCVRF,
						Raws: e.r.Paths(),
					}
				}
				if !slices.ContainsFunc(skb.SupersededBy, func(s microsoftkbSupersededByTypes.SupersededBy) bool {
					return s.KBID == kbID
				}) {
					skb.SupersededBy = append(skb.SupersededBy, microsoftkbSupersededByTypes.SupersededBy{KBID: kbID})
				}
				if !slices.Contains(skb.Products, criterionProductName) {
					skb.Products = append(skb.Products, criterionProductName)
				}
				kbm[r.Supercedence] = skb
			}
		}
	}
	return nil
}

// isCBLMarinerOrAzureLinux returns true if the product name references CBL-Mariner or Azure Linux.
// These products are handled by the dedicated Azure Linux OVAL data source instead.
func isCBLMarinerOrAzureLinux(productName string) bool {
	return strings.Contains(productName, "CBL Mariner") ||
		strings.Contains(productName, "CBL-Mariner") ||
		strings.Contains(productName, "Azure Linux")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
