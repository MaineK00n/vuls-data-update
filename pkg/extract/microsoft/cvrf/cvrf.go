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
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssv30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssv31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
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

	kbs := slices.Collect(maps.Values(kbm))
	microsoftutil.DeriveSupersedes(kbs)
	return datas, kbs, nil
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
	mitigations   []remediationTypes.Remediation
	workarounds   []remediationTypes.Remediation
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
	for _, r := range v.Remediations.Remediation {
		if r.Description == "" {
			continue
		}
		productIDs := r.ProductID
		if len(productIDs) == 0 {
			// An empty ProductID means the remediation applies to all products in the advisory.
			productIDs = v.ProductStatuses.Status.ProductID
		}
		rem := remediationTypes.Remediation{
			Source:      "secure@microsoft.com",
			Description: r.Description,
		}
		switch r.Type {
		case "Mitigation":
			for _, pid := range productIDs {
				pi := productInfoMap[pid]
				pi.mitigations = append(pi.mitigations, rem)
				productInfoMap[pid] = pi
			}
		case "Workaround":
			for _, pid := range productIDs {
				pi := productInfoMap[pid]
				pi.workarounds = append(pi.workarounds, rem)
				productInfoMap[pid] = pi
			}
		default:
		}
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
			Mitigations: pi.mitigations,
			Workarounds: pi.workarounds,
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
			Mitigations: pi.mitigations,
			Workarounds: pi.workarounds,
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

	// Track which product IDs are covered by Vendor Fix remediations.
	coveredProductIDs := make(map[string]struct{})

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

				// Mark the product as covered so that the ProductStatuses fallback
				// does not incorrectly register it as unfixed. This must happen
				// before the nil check below because some Vendor Fix entries
				// (e.g. "Click to Run") carry neither a KB ID nor a FixedBuild,
				// yet the product IS fixed via an auto-update channel.
				coveredProductIDs[pid] = struct{}{}

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
				if twinKBID, ok := kbCumulativeTwins[[2]string{criterionProductName, r.Description}]; ok {
					cns = append(cns, *buildKBCriterion(criterionProductName, twinKBID))
				}
				if fixedBuildCriterion != nil {
					cns = append(cns, *fixedBuildCriterion)
				}

				appendConditions(conditionsByEcosystem, tag, cns)
			}
		case "Release Notes", "Known Issue", "Mitigation", "Workaround":
		default:
			return nil, errors.Errorf("unexpected remediation type. expected: %q, actual: %q", []string{"Vendor Fix", "Release Notes", "Known Issue", "Mitigation", "Workaround"}, r.Type)
		}
	}

	// For products listed in ProductStatuses but not covered by any Vendor Fix
	// remediation, use fixedBuildOverrides if available (e.g. Edge), otherwise
	// register as unfixed.
	for _, pid := range v.ProductStatuses.Status.ProductID {
		if _, ok := coveredProductIDs[pid]; ok {
			continue
		}

		productName, ok := products[pid]
		if !ok {
			return nil, errors.Errorf("product ID %q not found in product tree for %s", pid, v.CVE)
		}

		if isCBLMarinerOrAzureLinux(productName) {
			continue
		}

		tag := segmentTypes.DetectionTag(productName)
		criterionProductName := microsoftutil.NormalizeProductName(productName)

		fixedBuildCriterion, err := buildFixedBuildCriterion(v.CVE, criterionProductName, "")
		if err != nil {
			return nil, errors.Wrap(err, "build fixed build criterion")
		}

		if fixedBuildCriterion != nil {
			appendConditions(conditionsByEcosystem, tag, []criterionTypes.Criterion{*fixedBuildCriterion})
			continue
		}

		appendConditions(conditionsByEcosystem, tag, []criterionTypes.Criterion{{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnfixed},
				Package: criterionpackageTypes.Package{
					Type:   criterionpackageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{Name: criterionProductName},
				},
			},
		}})
	}

	return conditionsByEcosystem, nil
}

func appendConditions(conditionsByEcosystem map[ecosystemTypes.Ecosystem][]conditionTypes.Condition, tag segmentTypes.DetectionTag, cns []criterionTypes.Criterion) {
	conditions := conditionsByEcosystem[ecosystemTypes.EcosystemTypeMicrosoft]

	idx := slices.IndexFunc(conditions, func(c conditionTypes.Condition) bool {
		return c.Tag == tag
	})
	if idx == -1 {
		conditions = append(conditions, conditionTypes.Condition{
			Criteria: criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			Tag:      tag,
		})
		idx = len(conditions) - 1
	}

	for _, cn := range cns {
		switch cn.Type {
		case criterionTypes.CriterionTypeKB:
			// KB criterions go under a nested AND sub-criteria so that
			// dual-track KBs (Monthly Rollup + Security Only) require ALL
			// to be unapplied before reporting a vulnerability.
			if len(conditions[idx].Criteria.Criterias) == 0 {
				conditions[idx].Criteria.Criterias = []criteriaTypes.Criteria{{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
				}}
			}
			if !slices.ContainsFunc(conditions[idx].Criteria.Criterias[0].Criterions, func(e criterionTypes.Criterion) bool {
				return criterionTypes.Compare(e, cn) == 0
			}) {
				conditions[idx].Criteria.Criterias[0].Criterions = append(conditions[idx].Criteria.Criterias[0].Criterions, cn)
			}
		default:
			// Version criterions go directly under the top-level OR.
			if !slices.ContainsFunc(conditions[idx].Criteria.Criterions, func(e criterionTypes.Criterion) bool {
				return criterionTypes.Compare(e, cn) == 0
			}) {
				conditions[idx].Criteria.Criterions = append(conditions[idx].Criteria.Criterions, cn)
			}
		}
	}

	conditionsByEcosystem[ecosystemTypes.EcosystemTypeMicrosoft] = conditions
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
	//  - Semicolon-separated compound versions (e.g. "3.0.6920.8954; 2.0.50727.8970")
	//    used by .NET Framework products bundling multiple framework versions
	if fixedBuild[0] < '0' || fixedBuild[0] > '9' || strings.Contains(fixedBuild, "x") || !strings.Contains(fixedBuild, ".") || strings.Contains(fixedBuild, ";") {
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

		// Microsoft Defender Antimalware Platform
		case "Microsoft Defender Antimalware Platform":
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
			"Microsoft SQL Server 2022 for x64-based Systems (CU 24)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 5)",
			"Microsoft SQL Server 2022 for x64-based Systems (CU 8)",
			"Microsoft SQL Server 2022 for x64-based Systems (GDR)",
			"Microsoft SQL Server 2025 for x64-based Systems (CU2)",
			"Microsoft SQL Server 2025 for x64-based Systems (CU3)",
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
			"Microsoft Visual Studio 2026 Version 18.3",
			"Microsoft Visual Studio 2026 Version 18.4",
			"Microsoft Visual Studio 2026 Version 18.5":
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

	// Microsoft Defender for Endpoint for Linux (FixedBuild is 4-part, parser expects 3-part)
	// 2026-Feb (CVE-2026-21537, FixedBuild "1.0.9.0" has extra revision segment)
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
	{"CVE-2021-38655", "Office Online Server", "10378.20000"}:                                 "16.0.10378.20000",
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
	// 2022-Feb (CVE-2022-21965, FixedBuild "1416/..." has numeric prefix)
	{"CVE-2022-21965", "Microsoft Teams for Android", "1416/1.0.0.2021040701"}: "1.0.0.2021040701",
	// 2025-Aug (CVE-2025-53783, FixedBuild "1416/..." has numeric prefix)
	{"CVE-2025-53783", "Microsoft Teams for Android", "1416/1.0.0.2025102802"}: "1.0.0.2025102802",

	// Teams Panels / Phones (FixedBuild "1449/..." has numeric prefix before slash)
	// 2025-Aug (CVE-2025-53783, FixedBuild "1449/..." has numeric prefix)
	{"CVE-2025-53783", "Teams Panels", "1449/1.0.97.2025102203"}: "1.0.97.2025102203",
	{"CVE-2025-53783", "Teams Phones", "1449/1.0.94.2025168802"}: "1.0.94.2025168802",

	// Microsoft Teams for iOS (FixedBuild has trailing parenthetical build ID)
	// 2025-Jul (CVE-2025-49731, FixedBuild has trailing parenthetical build ID)
	{"CVE-2025-49731", "Microsoft Teams for iOS", "7.10.1 (100772025102901)"}: "7.10.1",
	// 2025-Aug (CVE-2025-53783, FixedBuild has trailing parenthetical build ID)
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
	// 2020-Feb (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2020-0689", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2020-Jul (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"ADV200011", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"ADV200011", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2021-May (IE Cumulative, FixedBuild "6.0"/"6.1"/"6.2" matches OS major.minor but is a truncated IE revision)
	{"CVE-2021-26419", "Internet Explorer 9 on Windows Server 2008 for 32-bit Systems Service Pack 2", "6.0"}:        "",
	{"CVE-2021-26419", "Internet Explorer 9 on Windows Server 2008 for x64-based Systems Service Pack 2", "6.0"}:     "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1", "6.1"}:                 "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows 7 for x64-based Systems Service Pack 1", "6.1"}:              "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows Server 2008 R2 for x64-based Systems Service Pack 1", "6.1"}: "",
	{"CVE-2021-26419", "Internet Explorer 11 on Windows Server 2012", "6.2"}:                                         "",
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
	// 2022-Aug (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2022-34301", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34301", "Windows 10 for x64-based Systems", "1.002"}: "",
	{"CVE-2022-34302", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34302", "Windows 10 for x64-based Systems", "1.002"}: "",
	{"CVE-2022-34303", "Windows 10 for 32-bit Systems", "1.002"}:    "",
	{"CVE-2022-34303", "Windows 10 for x64-based Systems", "1.002"}: "",
	// 2023-Feb (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{"CVE-2023-21805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "1.1.0.0"}:                            "",
	{"CVE-2023-21805", "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "1.1.0.0"}: "",
	{"CVE-2023-21805", "Windows Server 2008 for 32-bit Systems Service Pack 2", "1.1.0.0"}:                                  "",
	{"CVE-2023-21805", "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:       "",
	{"CVE-2023-21805", "Windows Server 2008 for x64-based Systems Service Pack 2", "1.1.0.0"}:                               "",
	{"CVE-2023-21805", "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "1.1.0.0"}:    "",
	{"CVE-2023-21805", "Windows Server 2012", "1.1.0.0"}:                                                                    "",
	{"CVE-2023-21805", "Windows Server 2012 (Server Core installation)", "1.1.0.0"}:                                         "",
	// 2023-May (Windows 11 24H2 x64, FixedBuild "0.0.26200.4652" is a typo for "10.0.26100.4652" — the ARM64 entry has the correct value)
	{"CVE-2023-24932", "Windows 11 Version 24H2 for x64-based Systems", "0.0.26200.4652"}: "10.0.26100.4652",
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
	// 2023-Aug (IE Cumulative, FixedBuild "10.0.0.0" is a revision number, not a Windows OS build)
	{"CVE-2023-35384", "Windows Server 2012 R2", "10.0.0.0"}:                            "",
	{"CVE-2023-35384", "Windows Server 2012 R2 (Server Core installation)", "10.0.0.0"}: "",
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
	// 2023-Dec (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{"CVE-2023-35628", "Windows Server 2012 R2", "1.002"}: "",
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
	// 2025-Jan (IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
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
	// 2026-Apr (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{"CVE-2026-32077", "Windows Server 2012", "1.000"}:                               "",
	{"CVE-2026-32077", "Windows Server 2012 (Server Core installation)", "1.000"}:    "",
	{"CVE-2026-32077", "Windows Server 2012 R2", "1.000"}:                            "",
	{"CVE-2026-32077", "Windows Server 2012 R2 (Server Core installation)", "1.000"}: "",

	// Windows OS (FixedBuild leaked from a sibling servicing branch: a single Vendor Fix
	// Remediation grouped products from multiple servicing branches but specified only
	// one branch's build value; rewrite only the third component of "10.0.X.Y" to the
	// product's known servicing-branch build major, preserving the per-CVE fourth
	// component that is shared across branches.)
	// 2023-Feb (Win11 21H2 (ARM64) tagged 10.0.22621.x; Win11 21H2 (x64) tagged 10.0.22621.x)
	{"CVE-2023-21684", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21684", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21685", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21685", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21686", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21686", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21687", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21687", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21688", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21688", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21689", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21689", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21690", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21690", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21691", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21691", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21692", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21692", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21693", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21693", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21694", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21694", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21695", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21695", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21700", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21700", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21701", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21701", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21702", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21702", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21797", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21797", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21798", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21798", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21799", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21799", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21801", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21801", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21802", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21802", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21804", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21804", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21805", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21805", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21811", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21811", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21812", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21812", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21813", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21813", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21816", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21816", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21817", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21817", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21818", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21818", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21819", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21819", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21820", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21820", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21822", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21822", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-21823", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-21823", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	{"CVE-2023-23376", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"}: "10.0.22000.1574",
	{"CVE-2023-23376", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"}:   "10.0.22000.1574",
	// 2023-Dec (Win11 23H2 (ARM64) tagged 10.0.22621.x)
	{"CVE-2023-20588", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-21740", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35628", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35630", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35631", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35634", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35635", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35639", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35641", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35642", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-35644", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36003", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36004", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36005", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36006", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36011", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36391", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	{"CVE-2023-36696", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"}: "10.0.22631.2861",
	// 2024-Aug (Win11 21H2 (ARM64) tagged 10.0.19044.x; Win11 21H2 (x64) tagged 10.0.19044.x; Win11 24H2 (x64) tagged 10.0.22621.x)
	{"CVE-2022-2601", "Windows 11 Version 24H2 for x64-based Systems", "10.0.22621.5189"}:    "10.0.26100.5189",
	{"CVE-2023-40547", "Windows 11 Version 24H2 for x64-based Systems", "10.0.22621.5189"}:   "10.0.26100.5189",
	{"CVE-2024-21302", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.19044.5737"}: "10.0.22000.5737",
	{"CVE-2024-21302", "Windows 11 Version 21H2 for x64-based Systems", "10.0.19044.5737"}:   "10.0.22000.5737",
	// 2024-Sep (Win11 23H2 (x64) tagged 10.0.22621.x)
	{"CVE-2024-43495", "Windows 11 Version 23H2 for x64-based Systems", "10.0.22621.3880"}: "10.0.22631.3880",
	// 2025-Jun (Win11 23H2 (ARM64) tagged 10.0.22621.x; Win11 23H2 (x64) tagged 10.0.22621.x)
	{"CVE-2025-47969", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.5335"}: "10.0.22631.5335",
	{"CVE-2025-47969", "Windows 11 Version 23H2 for x64-based Systems", "10.0.22621.5335"}:   "10.0.22631.5335",
	// 2025-Jul (Server 2025 tagged 10.0.26200.x; Server 2025 Core tagged 10.0.26200.x)
	{"CVE-2025-49735", "Windows Server 2025", "10.0.26200.4349"}:                            "10.0.26100.4349",
	{"CVE-2025-49735", "Windows Server 2025 (Server Core installation)", "10.0.26200.4349"}: "10.0.26100.4349",
	// 2025-Aug (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 23H2 (x64) tagged 10.0.22621.x)
	{"CVE-2025-53789", "Windows 11 Version 22H2 for ARM64-based Systems", "10.0.22631.5624"}: "10.0.22621.5624",
	{"CVE-2025-53789", "Windows 11 Version 23H2 for x64-based Systems", "10.0.22621.5624"}:   "10.0.22631.5624",
	{"CVE-2025-55230", "Windows 11 Version 23H2 for x64-based Systems", "10.0.22621.5624"}:   "10.0.22631.5624",
	// 2025-Sep (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 22H2 (x64) tagged 10.0.22631.x)
	{"CVE-2025-59220", "Windows 11 Version 22H2 for ARM64-based Systems", "10.0.22631.5909"}: "10.0.22621.5909",
	{"CVE-2025-59220", "Windows 11 Version 22H2 for x64-based Systems", "10.0.22631.5909"}:   "10.0.22621.5909",
	// 2025-Oct (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 22H2 (x64) tagged 10.0.22631.x)
	{"CVE-2025-59289", "Windows 11 Version 22H2 for ARM64-based Systems", "10.0.22631.5909"}: "10.0.22621.5909",
	{"CVE-2025-59289", "Windows 11 Version 22H2 for x64-based Systems", "10.0.22631.5909"}:   "10.0.22621.5909",
	{"CVE-2025-59290", "Windows 11 Version 22H2 for ARM64-based Systems", "10.0.22631.5909"}: "10.0.22621.5909",
	{"CVE-2025-59290", "Windows 11 Version 22H2 for x64-based Systems", "10.0.22631.5909"}:   "10.0.22621.5909",
	{"CVE-2025-59502", "Windows 11 Version 22H2 for ARM64-based Systems", "10.0.22631.5909"}: "10.0.22621.5909",
	{"CVE-2025-59502", "Windows 11 Version 22H2 for x64-based Systems", "10.0.22631.5909"}:   "10.0.22621.5909",
	// 2025-Dec (Win11 25H2 (ARM64) tagged 10.0.26100.x; Win11 25H2 (x64) tagged 10.0.26100.x)
	{"CVE-2025-54100", "Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26100.7392"}: "10.0.26200.7392",
	{"CVE-2025-54100", "Windows 11 Version 25H2 for x64-based Systems", "10.0.26100.7392"}:   "10.0.26200.7392",
	// 2026-Mar (Win11 25H2 (ARM64) tagged 10.0.26100.x)
	{"CVE-2026-25172", "Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26100.7982"}: "10.0.26200.7982",
	{"CVE-2026-25173", "Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26100.7982"}: "10.0.26200.7982",
	{"CVE-2026-26111", "Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26100.7982"}: "10.0.26200.7982",
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

// kbCumulativeTwins maps (CVRF product name, source KB) pairs to the
// chain-bearing twin KB (Cumulative Update / Security Monthly Quality
// Rollup) of a chain-less Delta Update / Security Only Quality Update.
//
// CVRF Vendor Fix Remediations from 2017-2020 sometimes list only the
// chain-less variant whose MSUC entry has empty supersedes/supersededby
// chains. vuls2's backward-supersedes walk cannot then prove coverage from
// a host's applied LCU/Rollup, causing FPs even though the host is patched.
// Adding the twin KB as an additional KB criterion lets the supersession
// chain resolve.
//
// The product name is part of the key (parallel to fixedBuildOverrides) so
// each entry is exact-match and self-validating: no fuzzy/substring matching
// is performed at lookup time. Entries are generated from observed CVRF
// (productName, KBID) tuples, normalized via microsoftutil.NormalizeProductName.
var kbCumulativeTwins = map[[2]string]string{
	// 2017-May (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4019472"}:               "4023680",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4019472"}:            "4023680",
	{"Internet Explorer 11 on Windows Server 2016", "4019472"}:                                      "4023680",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for 32-bit Systems", "4019472"}:       "4023680",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for x64-based Systems", "4019472"}:    "4023680",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016", "4019472"}:                              "4023680",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016 (Server Core installation)", "4019472"}:   "4023680",
	{"Microsoft .NET Framework 4.6.2 on Windows 10 Version 1607 for 32-bit Systems", "4019472"}:     "4023680",
	{"Microsoft .NET Framework 4.6.2 on Windows 10 Version 1607 for x64-based Systems", "4019472"}:  "4023680",
	{"Microsoft .NET Framework 4.6.2 on Windows Server 2016", "4019472"}:                            "4023680",
	{"Microsoft .NET Framework 4.6.2 on Windows Server 2016 (Server Core installation)", "4019472"}: "4023680",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4019472"}:    "4023680",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4019472"}: "4023680",
	{"Windows 10 Version 1607 for 32-bit Systems", "4019472"}:                                       "4023680",
	{"Windows 10 Version 1607 for x64-based Systems", "4019472"}:                                    "4023680",
	{"Windows Server 2016", "4019472"}:                                                              "4023680",
	{"Windows Server 2016 (Server Core installation)", "4019472"}:                                   "4023680",

	// 2017-May (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4019213"}:                                                         "4019215",
	{"Windows 8.1 for x64-based Systems", "4019213"}:                                                      "4019215",
	{"Windows Server 2012 R2", "4019213"}:                                                                 "4019215",
	{"Windows Server 2012 R2 (Server Core installation)", "4019213"}:                                      "4019215",
	{"Windows Server 2012", "4019214"}:                                                                    "4019216",
	{"Windows Server 2012 (Server Core installation)", "4019214"}:                                         "4019216",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4019263"}:                                            "4019264",
	{"Windows 7 for x64-based Systems Service Pack 1", "4019263"}:                                         "4019264",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4019263"}:                        "4019264",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4019263"}:                            "4019264",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4019263"}: "4019264",

	// 2017-Jun (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4022722"}:                                            "4022719",
	{"Windows 7 for x64-based Systems Service Pack 1", "4022722"}:                                         "4022719",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4022722"}:                        "4022719",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4022722"}:                            "4022719",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4022722"}: "4022719",
	{"Windows Server 2012", "4022718"}:                                                                    "4022724",
	{"Windows Server 2012 (Server Core installation)", "4022718"}:                                         "4022724",
	{"Windows 8.1 for 32-bit Systems", "4022717"}:                                                         "4022726",
	{"Windows 8.1 for x64-based Systems", "4022717"}:                                                      "4022726",
	{"Windows Server 2012 R2", "4022717"}:                                                                 "4022726",
	{"Windows Server 2012 R2 (Server Core installation)", "4022717"}:                                      "4022726",

	// 2017-Jul (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4025343"}:                                                                    "4025331",
	{"Windows Server 2012 (Server Core installation)", "4025343"}:                                         "4025331",
	{"Windows 8.1 for 32-bit Systems", "4025333"}:                                                         "4025336",
	{"Windows 8.1 for x64-based Systems", "4025333"}:                                                      "4025336",
	{"Windows Server 2012 R2", "4025333"}:                                                                 "4025336",
	{"Windows Server 2012 R2 (Server Core installation)", "4025333"}:                                      "4025336",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4025337"}:                                            "4025341",
	{"Windows 7 for x64-based Systems Service Pack 1", "4025337"}:                                         "4025341",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4025337"}:                        "4025341",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4025337"}:                            "4025341",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4025337"}: "4025341",

	// 2017-Aug (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4034658"}:               "4039396",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4034658"}:            "4039396",
	{"Internet Explorer 11 on Windows Server 2016", "4034658"}:                                      "4039396",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4034658"}:    "4039396",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4034658"}: "4039396",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4034658"}:                           "4039396",
	{"Windows 10 Version 1607 for 32-bit Systems", "4034658"}:                                       "4039396",
	{"Windows 10 Version 1607 for x64-based Systems", "4034658"}:                                    "4039396",
	{"Windows Server 2016", "4034658"}:                                                              "4039396",
	{"Windows Server 2016 (Server Core installation)", "4034658"}:                                   "4039396",

	// 2017-Aug (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4034679"}:                                            "4034664",
	{"Windows 7 for x64-based Systems Service Pack 1", "4034679"}:                                         "4034664",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4034679"}:                        "4034664",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4034679"}:                            "4034664",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4034679"}: "4034664",
	{"Windows Server 2012", "4034666"}:                                                                    "4034665",
	{"Windows Server 2012 (Server Core installation)", "4034666"}:                                         "4034665",
	{"Windows 8.1 for 32-bit Systems", "4034672"}:                                                         "4034681",
	{"Windows 8.1 for x64-based Systems", "4034672"}:                                                      "4034681",
	{"Windows Server 2012 R2", "4034672"}:                                                                 "4034681",
	{"Windows Server 2012 R2 (Server Core installation)", "4034672"}:                                      "4034681",

	// 2017-Sep (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4038779"}:                                            "4038777",
	{"Windows 7 for x64-based Systems Service Pack 1", "4038779"}:                                         "4038777",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4038779"}:                        "4038777",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4038779"}:                            "4038777",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4038779"}: "4038777",
	{"Windows 8.1 for 32-bit Systems", "4038793"}:                                                         "4038792",
	{"Windows 8.1 for x64-based Systems", "4038793"}:                                                      "4038792",
	{"Windows Server 2012 R2", "4038793"}:                                                                 "4038792",
	{"Windows Server 2012 R2 (Server Core installation)", "4038793"}:                                      "4038792",
	{"Windows Server 2012", "4038786"}:                                                                    "4038799",
	{"Windows Server 2012 (Server Core installation)", "4038786"}:                                         "4038799",

	// 2017-Oct (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4041678"}:                                            "4041681",
	{"Windows 7 for x64-based Systems Service Pack 1", "4041678"}:                                         "4041681",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4041678"}:                        "4041681",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4041678"}:                            "4041681",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4041678"}: "4041681",
	{"Windows Server 2012", "4041679"}:                                                                    "4041690",
	{"Windows Server 2012 (Server Core installation)", "4041679"}:                                         "4041690",
	{"Windows 8.1 for 32-bit Systems", "4041687"}:                                                         "4041693",
	{"Windows 8.1 for x64-based Systems", "4041687"}:                                                      "4041693",
	{"Windows Server 2012 R2", "4041687"}:                                                                 "4041693",
	{"Windows Server 2012 R2 (Server Core installation)", "4041687"}:                                      "4041693",

	// 2017-Nov (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4048955"}:               "4051963",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4048955"}:            "4051963",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4048955"}:    "4051963",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4048955"}: "4051963",
	{"Windows 10 Version 1709 for 32-bit Systems", "4048955"}:                                       "4051963",
	{"Windows 10 Version 1709 for x64-based Systems", "4048955"}:                                    "4051963",
	{"Windows Server, Version 1709 (Server Core installation)", "4048955"}:                          "4051963",

	// 2017-Nov (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4048960"}:                                            "4048957",
	{"Windows 7 for x64-based Systems Service Pack 1", "4048960"}:                                         "4048957",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4048960"}:                        "4048957",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4048960"}:                            "4048957",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4048960"}: "4048957",
	{"Windows 8.1 for 32-bit Systems", "4048961"}:                                                         "4048958",
	{"Windows 8.1 for x64-based Systems", "4048961"}:                                                      "4048958",
	{"Windows Server 2012 R2", "4048961"}:                                                                 "4048958",
	{"Windows Server 2012 R2 (Server Core installation)", "4048961"}:                                      "4048958",
	{"Windows Server 2012", "4048962"}:                                                                    "4048959",
	{"Windows Server 2012 (Server Core installation)", "4048962"}:                                         "4048959",

	// 2017-Dec (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4054521"}:                                            "4054518",
	{"Windows 7 for x64-based Systems Service Pack 1", "4054521"}:                                         "4054518",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4054521"}:                        "4054518",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4054521"}:                            "4054518",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4054521"}: "4054518",
	{"Windows 8.1 for 32-bit Systems", "4054522"}:                                                         "4054519",
	{"Windows 8.1 for x64-based Systems", "4054522"}:                                                      "4054519",
	{"Windows Server 2012 R2", "4054522"}:                                                                 "4054519",
	{"Windows Server 2012 R2 (Server Core installation)", "4054522"}:                                      "4054519",
	{"Windows Server 2012", "4054523"}:                                                                    "4054520",
	{"Windows Server 2012 (Server Core installation)", "4054523"}:                                         "4054520",

	// 2018-Jan (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4056897"}:                                            "4056894",
	{"Windows 7 for x64-based Systems Service Pack 1", "4056897"}:                                         "4056894",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4056897"}:                        "4056894",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4056897"}:                            "4056894",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4056897"}: "4056894",
	{"Windows 8.1 for 32-bit Systems", "4056898"}:                                                         "4056895",
	{"Windows 8.1 for x64-based Systems", "4056898"}:                                                      "4056895",
	{"Windows Server 2012 R2", "4056898"}:                                                                 "4056895",
	{"Windows Server 2012 R2 (Server Core installation)", "4056898"}:                                      "4056895",
	{"Windows Server 2012", "4056899"}:                                                                    "4056896",
	{"Windows Server 2012 (Server Core installation)", "4056899"}:                                         "4056896",

	// 2018-Feb (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4074589"}:                                                                    "4074593",
	{"Windows Server 2012 (Server Core installation)", "4074589"}:                                         "4074593",
	{"Windows 8.1 for 32-bit Systems", "4074597"}:                                                         "4074594",
	{"Windows 8.1 for x64-based Systems", "4074597"}:                                                      "4074594",
	{"Windows Server 2012 R2", "4074597"}:                                                                 "4074594",
	{"Windows Server 2012 R2 (Server Core installation)", "4074597"}:                                      "4074594",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4074587"}:                                            "4074598",
	{"Windows 7 for x64-based Systems Service Pack 1", "4074587"}:                                         "4074598",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4074587"}:                        "4074598",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4074587"}:                            "4074598",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4074587"}: "4074598",

	// 2018-Mar (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4088878"}:                                            "4088875",
	{"Windows 7 for x64-based Systems Service Pack 1", "4088878"}:                                         "4088875",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4088878"}:                        "4088875",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4088878"}:                            "4088875",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4088878"}: "4088875",
	{"Windows 8.1 for 32-bit Systems", "4088879"}:                                                         "4088876",
	{"Windows 8.1 for x64-based Systems", "4088879"}:                                                      "4088876",
	{"Windows Server 2012 R2", "4088879"}:                                                                 "4088876",
	{"Windows Server 2012 R2 (Server Core installation)", "4088879"}:                                      "4088876",
	{"Windows Server 2012", "4088880"}:                                                                    "4088877",
	{"Windows Server 2012 (Server Core installation)", "4088880"}:                                         "4088877",

	// 2018-Apr (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4093112"}:               "4093105",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4093112"}:            "4093105",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4093112"}:    "4093105",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4093112"}: "4093105",
	{"Windows 10 Version 1709 for 32-bit Systems", "4093112"}:                                       "4093105",
	{"Windows 10 Version 1709 for x64-based Systems", "4093112"}:                                    "4093105",
	{"Windows Server, Version 1709 (Server Core installation)", "4093112"}:                          "4093105",
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4093119"}:               "4093120",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4093119"}:            "4093120",
	{"Internet Explorer 11 on Windows Server 2016", "4093119"}:                                      "4093120",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4093119"}:    "4093120",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4093119"}: "4093120",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4093119"}:                           "4093120",
	{"Windows 10 Version 1607 for 32-bit Systems", "4093119"}:                                       "4093120",
	{"Windows 10 Version 1607 for x64-based Systems", "4093119"}:                                    "4093120",
	{"Windows Server 2016", "4093119"}:                                                              "4093120",
	{"Windows Server 2016 (Server Core installation)", "4093119"}:                                   "4093120",

	// 2018-Apr (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4093115"}:                                                         "4093114",
	{"Windows 8.1 for x64-based Systems", "4093115"}:                                                      "4093114",
	{"Windows Server 2012 R2", "4093115"}:                                                                 "4093114",
	{"Windows Server 2012 R2 (Server Core installation)", "4093115"}:                                      "4093114",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4093108"}:                                            "4093118",
	{"Windows 7 for x64-based Systems Service Pack 1", "4093108"}:                                         "4093118",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4093108"}:                        "4093118",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4093108"}:                            "4093118",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4093108"}: "4093118",
	{"Windows Server 2012", "4093122"}:                                                                    "4093123",
	{"Windows Server 2012 (Server Core installation)", "4093122"}:                                         "4093123",

	// 2018-May (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4103727"}:                         "4103714",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4103727"}:                      "4103714",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4103727"}:                 "4103714",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4103727"}:              "4103714",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4103727"}:    "4103714",
	{"Microsoft .NET Framework 4.7.1 on Windows 10 Version 1709 for 32-bit Systems", "4103727"}:               "4103714",
	{"Microsoft .NET Framework 4.7.1 on Windows 10 Version 1709 for x64-based Systems", "4103727"}:            "4103714",
	{"Microsoft .NET Framework 4.7.1 on Windows Server, Version 1709 (Server Core installation)", "4103727"}:  "4103714",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4103727"}:              "4103714",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4103727"}:           "4103714",
	{"Windows 10 Version 1709 for 32-bit Systems", "4103727"}:                                                 "4103714",
	{"Windows 10 Version 1709 for x64-based Systems", "4103727"}:                                              "4103714",
	{"Windows Server, Version 1709 (Server Core installation)", "4103727"}:                                    "4103714",
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4103723"}:                         "4103720",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4103723"}:                      "4103720",
	{"Internet Explorer 11 on Windows Server 2016", "4103723"}:                                                "4103720",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for 32-bit Systems", "4103723"}:                 "4103720",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for x64-based Systems", "4103723"}:              "4103720",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016", "4103723"}:                                        "4103720",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016 (Server Core installation)", "4103723"}:             "4103720",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1 on Windows 10 Version 1607 for 32-bit Systems", "4103723"}:     "4103720",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1 on Windows 10 Version 1607 for x64-based Systems", "4103723"}:  "4103720",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1 on Windows Server 2016", "4103723"}:                            "4103720",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1 on Windows Server 2016 (Server Core installation)", "4103723"}: "4103720",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4103723"}:              "4103720",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4103723"}:           "4103720",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4103723"}:                                     "4103720",
	{"Windows 10 Version 1607 for 32-bit Systems", "4103723"}:                                                 "4103720",
	{"Windows 10 Version 1607 for x64-based Systems", "4103723"}:                                              "4103720",
	{"Windows Server 2016", "4103723"}:                                                                        "4103720",
	{"Windows Server 2016 (Server Core installation)", "4103723"}:                                             "4103720",

	// 2018-May (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4103712"}:                                            "4103718",
	{"Windows 7 for x64-based Systems Service Pack 1", "4103712"}:                                         "4103718",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4103712"}:                        "4103718",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4103712"}:                            "4103718",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4103712"}: "4103718",
	{"Windows 8.1 for 32-bit Systems", "4103715"}:                                                         "4103725",
	{"Windows 8.1 for x64-based Systems", "4103715"}:                                                      "4103725",
	{"Windows Server 2012 R2", "4103715"}:                                                                 "4103725",
	{"Windows Server 2012 R2 (Server Core installation)", "4103715"}:                                      "4103725",
	{"Windows Server 2012", "4103726"}:                                                                    "4103730",
	{"Windows Server 2012 (Server Core installation)", "4103726"}:                                         "4103730",

	// 2018-Jun (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4284819"}:               "4284822",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4284819"}:            "4284822",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4284819"}:    "4284822",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4284819"}: "4284822",
	{"Windows 10 Version 1709 for 32-bit Systems", "4284819"}:                                       "4284822",
	{"Windows 10 Version 1709 for x64-based Systems", "4284819"}:                                    "4284822",
	{"Windows Server, Version 1709 (Server Core installation)", "4284819"}:                          "4284822",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4284835"}:               "4338548",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4284835"}:            "4338548",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4284835"}:    "4338548",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4284835"}: "4338548",
	{"Windows 10 Version 1803 for 32-bit Systems", "4284835"}:                                       "4338548",
	{"Windows 10 Version 1803 for x64-based Systems", "4284835"}:                                    "4338548",
	{"Windows Server, Version 1803 (Server Core installation)", "4284835"}:                          "4338548",

	// 2018-Jun (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4284878"}:                                                         "4284815",
	{"Windows 8.1 for x64-based Systems", "4284878"}:                                                      "4284815",
	{"Windows Server 2012 R2", "4284878"}:                                                                 "4284815",
	{"Windows Server 2012 R2 (Server Core installation)", "4284878"}:                                      "4284815",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4284867"}:                                            "4284826",
	{"Windows 7 for x64-based Systems Service Pack 1", "4284867"}:                                         "4284826",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4284867"}:                        "4284826",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4284867"}:                            "4284826",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4284867"}: "4284826",
	{"Windows Server 2012", "4284846"}:                                                                    "4284855",
	{"Windows Server 2012 (Server Core installation)", "4284846"}:                                         "4284855",

	// 2018-Jul (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4338825"}:                               "4338817",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4338825"}:                            "4338817",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4338825"}:                       "4338817",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4338825"}:                    "4338817",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4338825"}:          "4338817",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4338825"}:               "4338817",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4338825"}:            "4338817",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4338825"}:  "4338817",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4338825"}:                     "4338817",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4338825"}:                  "4338817",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4338825"}:        "4338817",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4338825"}:                    "4338817",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4338825"}:                 "4338817",
	{"Windows 10 Version 1709 for 32-bit Systems", "4338825"}:                                                       "4338817",
	{"Windows 10 Version 1709 for x64-based Systems", "4338825"}:                                                    "4338817",
	{"Windows Server, Version 1709 (Server Core installation)", "4338825"}:                                          "4338817",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4338819"}:                               "4345421",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4338819"}:                            "4345421",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for 32-bit Systems", "4338819"}:                       "4345421",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for x64-based Systems", "4338819"}:                    "4345421",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1803 (Server Core installation)", "4338819"}:          "4345421",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for 32-bit Systems", "4338819"}:                     "4345421",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for x64-based Systems", "4338819"}:                  "4345421",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1803 (Server Core installation)", "4338819"}:        "4345421",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4338819"}:                    "4345421",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4338819"}:                 "4345421",
	{"Windows 10 Version 1803 for 32-bit Systems", "4338819"}:                                                       "4345421",
	{"Windows 10 Version 1803 for x64-based Systems", "4338819"}:                                                    "4345421",
	{"Windows Server, Version 1803 (Server Core installation)", "4338819"}:                                          "4345421",
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4338814"}:                               "4346877",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4338814"}:                            "4346877",
	{"Internet Explorer 11 on Windows Server 2016", "4338814"}:                                                      "4346877",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for 32-bit Systems", "4338814"}:                       "4346877",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1607 for x64-based Systems", "4338814"}:                    "4346877",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016", "4338814"}:                                              "4346877",
	{"Microsoft .NET Framework 3.5 on Windows Server 2016 (Server Core installation)", "4338814"}:                   "4346877",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2 on Windows 10 Version 1607 for 32-bit Systems", "4338814"}:     "4346877",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2 on Windows 10 Version 1607 for x64-based Systems", "4338814"}:  "4346877",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2 on Windows Server 2016", "4338814"}:                            "4346877",
	{"Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2 on Windows Server 2016 (Server Core installation)", "4338814"}: "4346877",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1607 for 32-bit Systems", "4338814"}:                     "4346877",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1607 for x64-based Systems", "4338814"}:                  "4346877",
	{"Microsoft .NET Framework 4.7.2 on Windows Server 2016", "4338814"}:                                            "4346877",
	{"Microsoft .NET Framework 4.7.2 on Windows Server 2016 (Server Core installation)", "4338814"}:                 "4346877",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4338814"}:                    "4346877",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4338814"}:                 "4346877",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4338814"}:                                           "4346877",
	{"Windows 10 Version 1607 for 32-bit Systems", "4338814"}:                                                       "4346877",
	{"Windows 10 Version 1607 for x64-based Systems", "4338814"}:                                                    "4346877",
	{"Windows Server 2016", "4338814"}:                                                                              "4346877",
	{"Windows Server 2016 (Server Core installation)", "4338814"}:                                                   "4346877",

	// 2018-Jul (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4338824"}:                                                         "4338815",
	{"Windows 8.1 for x64-based Systems", "4338824"}:                                                      "4338815",
	{"Windows Server 2012 R2", "4338824"}:                                                                 "4338815",
	{"Windows Server 2012 R2 (Server Core installation)", "4338824"}:                                      "4338815",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4338823"}:                                            "4338818",
	{"Windows 7 for x64-based Systems Service Pack 1", "4338823"}:                                         "4338818",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4338823"}:                        "4338818",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4338823"}:                            "4338818",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4338823"}: "4338818",
	{"Windows Server 2012", "4338820"}:                                                                    "4338830",
	{"Windows Server 2012 (Server Core installation)", "4338820"}:                                         "4338830",

	// 2018-Aug (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4343897"}:                              "4343893",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4343897"}:                           "4343893",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4343897"}:                      "4343893",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4343897"}:                   "4343893",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4343897"}:         "4343893",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4343897"}:              "4343893",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4343897"}:           "4343893",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4343897"}: "4343893",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4343897"}:                   "4343893",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4343897"}:                "4343893",
	{"Windows 10 Version 1709 for 32-bit Systems", "4343897"}:                                                      "4343893",
	{"Windows 10 Version 1709 for x64-based Systems", "4343897"}:                                                   "4343893",
	{"Windows Server, Version 1709 (Server Core installation)", "4343897"}:                                         "4343893",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4343909"}:                              "4346783",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4343909"}:                           "4346783",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for 32-bit Systems", "4343909"}:                      "4346783",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for x64-based Systems", "4343909"}:                   "4346783",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1803 (Server Core installation)", "4343909"}:         "4346783",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for 32-bit Systems", "4343909"}:                    "4346783",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for x64-based Systems", "4343909"}:                 "4346783",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1803 (Server Core installation)", "4343909"}:       "4346783",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4343909"}:                   "4346783",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4343909"}:                "4346783",
	{"Windows 10 Version 1803 for 32-bit Systems", "4343909"}:                                                      "4346783",
	{"Windows 10 Version 1803 for x64-based Systems", "4343909"}:                                                   "4346783",
	{"Windows Server, Version 1803 (Server Core installation)", "4343909"}:                                         "4346783",

	// 2018-Aug (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4343888"}:                                                         "4343898",
	{"Windows 8.1 for x64-based Systems", "4343888"}:                                                      "4343898",
	{"Windows Server 2012 R2", "4343888"}:                                                                 "4343898",
	{"Windows Server 2012 R2 (Server Core installation)", "4343888"}:                                      "4343898",
	{"Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1", "4343899"}:                    "4343900",
	{"Internet Explorer 11 on Windows 7 for x64-based Systems Service Pack 1", "4343899"}:                 "4343900",
	{"Internet Explorer 11 on Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4343899"}:    "4343900",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4343899"}:                                            "4343900",
	{"Windows 7 for x64-based Systems Service Pack 1", "4343899"}:                                         "4343900",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4343899"}:                        "4343900",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4343899"}:                            "4343900",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4343899"}: "4343900",
	{"Windows Server 2012", "4343896"}:                                                                    "4343901",
	{"Windows Server 2012 (Server Core installation)", "4343896"}:                                         "4343901",

	// 2018-Sep (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4457142"}:                              "4457136",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4457142"}:                           "4457136",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4457142"}:                      "4457136",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4457142"}:                   "4457136",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4457142"}:         "4457136",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4457142"}:              "4457136",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4457142"}:           "4457136",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4457142"}: "4457136",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4457142"}:                   "4457136",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4457142"}:                "4457136",
	{"Windows 10 Version 1709 for 32-bit Systems", "4457142"}:                                                      "4457136",
	{"Windows 10 Version 1709 for x64-based Systems", "4457142"}:                                                   "4457136",
	{"Windows Server, Version 1709 (Server Core installation)", "4457142"}:                                         "4457136",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4457128"}:                              "4464218",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4457128"}:                           "4464218",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for 32-bit Systems", "4457128"}:                      "4464218",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for x64-based Systems", "4457128"}:                   "4464218",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1803 (Server Core installation)", "4457128"}:         "4464218",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for 32-bit Systems", "4457128"}:                    "4464218",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for x64-based Systems", "4457128"}:                 "4464218",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1803 (Server Core installation)", "4457128"}:       "4464218",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4457128"}:                   "4464218",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4457128"}:                "4464218",
	{"Windows 10 Version 1803 for 32-bit Systems", "4457128"}:                                                      "4464218",
	{"Windows 10 Version 1803 for x64-based Systems", "4457128"}:                                                   "4464218",
	{"Windows Server, Version 1803 (Server Core installation)", "4457128"}:                                         "4464218",

	// 2018-Sep (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4457143"}:                                                         "4457129",
	{"Windows 8.1 for x64-based Systems", "4457143"}:                                                      "4457129",
	{"Windows Server 2012 R2", "4457143"}:                                                                 "4457129",
	{"Windows Server 2012 R2 (Server Core installation)", "4457143"}:                                      "4457129",
	{"Windows Server 2012", "4457140"}:                                                                    "4457135",
	{"Windows Server 2012 (Server Core installation)", "4457140"}:                                         "4457135",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4457145"}:                                            "4457144",
	{"Windows 7 for x64-based Systems Service Pack 1", "4457145"}:                                         "4457144",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4457145"}:                        "4457144",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4457145"}:                            "4457144",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4457145"}: "4457144",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4457984"}:                                  "4458010",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4457984"}:       "4458010",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4457984"}:                           "4458010",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4457984"}:                               "4458010",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4457984"}:    "4458010",

	// 2018-Oct (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4462917"}:               "4462928",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4462917"}:            "4462928",
	{"Internet Explorer 11 on Windows Server 2016", "4462917"}:                                      "4462928",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4462917"}:    "4462928",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4462917"}: "4462928",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4462917"}:                           "4462928",
	{"Windows 10 Version 1607 for 32-bit Systems", "4462917"}:                                       "4462928",
	{"Windows 10 Version 1607 for x64-based Systems", "4462917"}:                                    "4462928",
	{"Windows Server 2016", "4462917"}:                                                              "4462928",
	{"Windows Server 2016 (Server Core installation)", "4462917"}:                                   "4462928",
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4462918"}:               "4462932",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4462918"}:            "4462932",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4462918"}:    "4462932",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4462918"}: "4462932",
	{"Windows 10 Version 1709 for 32-bit Systems", "4462918"}:                                       "4462932",
	{"Windows 10 Version 1709 for x64-based Systems", "4462918"}:                                    "4462932",
	{"Windows Server, Version 1709 (Server Core installation)", "4462918"}:                          "4462932",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4462919"}:               "4462933",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4462919"}:            "4462933",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4462919"}:    "4462933",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4462919"}: "4462933",
	{"Windows 10 Version 1803 for 32-bit Systems", "4462919"}:                                       "4462933",
	{"Windows 10 Version 1803 for x64-based Systems", "4462919"}:                                    "4462933",
	{"Windows Server, Version 1803 (Server Core installation)", "4462919"}:                          "4462933",
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4462937"}:               "4462939",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4462937"}:            "4462939",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4462937"}:    "4462939",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4462937"}: "4462939",
	{"Windows 10 Version 1703 for 32-bit Systems", "4462937"}:                                       "4462939",
	{"Windows 10 Version 1703 for x64-based Systems", "4462937"}:                                    "4462939",

	// 2018-Oct (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4462915"}:                                            "4462923",
	{"Windows 7 for x64-based Systems Service Pack 1", "4462915"}:                                         "4462923",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4462915"}:                        "4462923",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4462915"}:                            "4462923",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4462915"}: "4462923",
	{"Windows 8.1 for 32-bit Systems", "4462941"}:                                                         "4462926",
	{"Windows 8.1 for x64-based Systems", "4462941"}:                                                      "4462926",
	{"Windows Server 2012 R2", "4462941"}:                                                                 "4462926",
	{"Windows Server 2012 R2 (Server Core installation)", "4462941"}:                                      "4462926",
	{"Windows Server 2012", "4462931"}:                                                                    "4462929",
	{"Windows Server 2012 (Server Core installation)", "4462931"}:                                         "4462929",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4463104"}:                                  "4463097",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4463104"}:       "4463097",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4463104"}:                           "4463097",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4463104"}:                               "4463097",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4463104"}:    "4463097",

	// 2018-Nov (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4467686"}:                 "4467681",
	{"Internet Explorer 11 on Windows 10 Version 1709 for ARM64-based Systems", "4467686"}:            "4467681",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4467686"}:              "4467681",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4467686"}:      "4467681",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for ARM64-based Systems", "4467686"}: "4467681",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4467686"}:   "4467681",
	{"Windows 10 Version 1709 for 32-bit Systems", "4467686"}:                                         "4467681",
	{"Windows 10 Version 1709 for ARM64-based Systems", "4467686"}:                                    "4467681",
	{"Windows 10 Version 1709 for x64-based Systems", "4467686"}:                                      "4467681",
	{"Windows Server, Version 1709 (Server Core installation)", "4467686"}:                            "4467681",
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4467696"}:                 "4467699",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4467696"}:              "4467699",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4467696"}:      "4467699",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4467696"}:   "4467699",
	{"Windows 10 Version 1703 for 32-bit Systems", "4467696"}:                                         "4467699",
	{"Windows 10 Version 1703 for x64-based Systems", "4467696"}:                                      "4467699",
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4467691"}:                 "4478877",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4467691"}:              "4478877",
	{"Internet Explorer 11 on Windows Server 2016", "4467691"}:                                        "4478877",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4467691"}:      "4478877",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4467691"}:   "4478877",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4467691"}:                             "4478877",
	{"Windows 10 Version 1607 for 32-bit Systems", "4467691"}:                                         "4478877",
	{"Windows 10 Version 1607 for x64-based Systems", "4467691"}:                                      "4478877",
	{"Windows Server 2016", "4467691"}:                                                                "4478877",
	{"Windows Server 2016 (Server Core installation)", "4467691"}:                                     "4478877",

	// 2018-Nov (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4467106"}:                                            "4467107",
	{"Windows 7 for x64-based Systems Service Pack 1", "4467106"}:                                         "4467107",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4467106"}:                        "4467107",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4467106"}:                            "4467107",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4467106"}: "4467107",
	{"Windows 8.1 for 32-bit Systems", "4467703"}:                                                         "4467697",
	{"Windows 8.1 for x64-based Systems", "4467703"}:                                                      "4467697",
	{"Windows RT 8.1", "4467703"}:                                                                         "4467697",
	{"Windows Server 2012 R2", "4467703"}:                                                                 "4467697",
	{"Windows Server 2012 R2 (Server Core installation)", "4467703"}:                                      "4467697",
	{"Windows Server 2012", "4467678"}:                                                                    "4467701",
	{"Windows Server 2012 (Server Core installation)", "4467678"}:                                         "4467701",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4467700"}:                                  "4467706",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4467700"}:       "4467706",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4467700"}:                           "4467706",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4467700"}:                               "4467706",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4467700"}:    "4467706",

	// 2018-Dec (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4471328"}:                                            "4471318",
	{"Windows 7 for x64-based Systems Service Pack 1", "4471328"}:                                         "4471318",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4471328"}:                        "4471318",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4471328"}:                            "4471318",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4471328"}: "4471318",
	{"Windows 8.1 for 32-bit Systems", "4471322"}:                                                         "4471320",
	{"Windows 8.1 for x64-based Systems", "4471322"}:                                                      "4471320",
	{"Windows Server 2012 R2", "4471322"}:                                                                 "4471320",
	{"Windows Server 2012 R2 (Server Core installation)", "4471322"}:                                      "4471320",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4471319"}:                                  "4471325",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4471319"}:       "4471325",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4471319"}:                           "4471325",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4471319"}:                               "4471325",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4471319"}:    "4471325",
	{"Windows Server 2012", "4471326"}:                                                                    "4471330",
	{"Windows Server 2012 (Server Core installation)", "4471326"}:                                         "4471330",

	// 2019-Jan (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4480973"}:                              "4480959",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4480973"}:                           "4480959",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1703 for 32-bit Systems", "4480973"}:                      "4480959",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1703 for x64-based Systems", "4480973"}:                   "4480959",
	{"Microsoft .NET Framework 4.7/4.7.1/4.7.2 on Windows 10 Version 1703 for 32-bit Systems", "4480973"}:          "4480959",
	{"Microsoft .NET Framework 4.7/4.7.1/4.7.2 on Windows 10 Version 1703 for x64-based Systems", "4480973"}:       "4480959",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4480973"}:                   "4480959",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4480973"}:                "4480959",
	{"Windows 10 Version 1703 for 32-bit Systems", "4480973"}:                                                      "4480959",
	{"Windows 10 Version 1703 for x64-based Systems", "4480973"}:                                                   "4480959",
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4480978"}:                              "4480967",
	{"Internet Explorer 11 on Windows 10 Version 1709 for ARM64-based Systems", "4480978"}:                         "4480967",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4480978"}:                           "4480967",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4480978"}:                      "4480967",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for ARM64-based Systems", "4480978"}:                 "4480967",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4480978"}:                   "4480967",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4480978"}:              "4480967",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for ARM64-based Systems", "4480978"}:         "4480967",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4480978"}:           "4480967",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4480978"}:                   "4480967",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for ARM64-based Systems", "4480978"}:              "4480967",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4480978"}:                "4480967",
	{"Windows 10 Version 1709 for 32-bit Systems", "4480978"}:                                                      "4480967",
	{"Windows 10 Version 1709 for ARM64-based Systems", "4480978"}:                                                 "4480967",
	{"Windows 10 Version 1709 for x64-based Systems", "4480978"}:                                                   "4480967",
	{"Windows Server, Version 1709 (Server Core installation)", "4480978"}:                                         "4480967",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4480966"}:                              "4480976",
	{"Internet Explorer 11 on Windows 10 Version 1803 for ARM64-based Systems", "4480966"}:                         "4480976",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4480966"}:                           "4480976",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for 32-bit Systems", "4480966"}:                      "4480976",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for ARM64-based Systems", "4480966"}:                 "4480976",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for x64-based Systems", "4480966"}:                   "4480976",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4480966"}:         "4480976",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1803 (Server Core installation)", "4480966"}:         "4480976",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4480966"}: "4480976",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for 32-bit Systems", "4480966"}:                    "4480976",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for ARM64-based Systems", "4480966"}:               "4480976",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for x64-based Systems", "4480966"}:                 "4480976",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1803 (Server Core installation)", "4480966"}:       "4480976",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4480966"}:                   "4480976",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for ARM64-based Systems", "4480966"}:              "4480976",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4480966"}:                "4480976",
	{"Windows 10 Version 1803 for 32-bit Systems", "4480966"}:                                                      "4480976",
	{"Windows 10 Version 1803 for ARM64-based Systems", "4480966"}:                                                 "4480976",
	{"Windows 10 Version 1803 for x64-based Systems", "4480966"}:                                                   "4480976",
	{"Windows Server, Version 1803 (Server Core installation)", "4480966"}:                                         "4480976",

	// 2019-Jan (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4480964"}:                                                         "4480963",
	{"Windows 8.1 for x64-based Systems", "4480964"}:                                                      "4480963",
	{"Windows Server 2012 R2", "4480964"}:                                                                 "4480963",
	{"Windows Server 2012 R2 (Server Core installation)", "4480964"}:                                      "4480963",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4480957"}:                                  "4480968",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4480957"}:       "4480968",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4480957"}:                           "4480968",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4480957"}:                               "4480968",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4480957"}:    "4480968",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4480960"}:                                            "4480970",
	{"Windows 7 for x64-based Systems Service Pack 1", "4480960"}:                                         "4480970",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4480960"}:                        "4480970",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4480960"}:                            "4480970",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4480960"}: "4480970",
	{"Windows Server 2012", "4480972"}:                                                                    "4480975",
	{"Windows Server 2012 (Server Core installation)", "4480972"}:                                         "4480975",

	// 2019-Feb (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4487020"}:                              "4487011",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4487020"}:                           "4487011",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1703 for 32-bit Systems", "4487020"}:                      "4487011",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1703 for x64-based Systems", "4487020"}:                   "4487011",
	{"Microsoft .NET Framework 4.7/4.7.1/4.7.2 on Windows 10 Version 1703 for 32-bit Systems", "4487020"}:          "4487011",
	{"Microsoft .NET Framework 4.7/4.7.1/4.7.2 on Windows 10 Version 1703 for x64-based Systems", "4487020"}:       "4487011",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4487020"}:                   "4487011",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4487020"}:                "4487011",
	{"Windows 10 Version 1703 for 32-bit Systems", "4487020"}:                                                      "4487011",
	{"Windows 10 Version 1703 for x64-based Systems", "4487020"}:                                                   "4487011",
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4486996"}:                              "4487021",
	{"Internet Explorer 11 on Windows 10 Version 1709 for ARM64-based Systems", "4486996"}:                         "4487021",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4486996"}:                           "4487021",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for 32-bit Systems", "4486996"}:                      "4487021",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for ARM64-based Systems", "4486996"}:                 "4487021",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1709 for x64-based Systems", "4486996"}:                   "4487021",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1709 (Server Core installation)", "4486996"}:         "4487021",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for 32-bit Systems", "4486996"}:              "4487021",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for ARM64-based Systems", "4486996"}:         "4487021",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows 10 Version 1709 for x64-based Systems", "4486996"}:           "4487021",
	{"Microsoft .NET Framework 4.7.1/4.7.2 on Windows Server, Version 1709 (Server Core installation)", "4486996"}: "4487021",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4486996"}:                   "4487021",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for ARM64-based Systems", "4486996"}:              "4487021",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4486996"}:                "4487021",
	{"Windows 10 Version 1709 for 32-bit Systems", "4486996"}:                                                      "4487021",
	{"Windows 10 Version 1709 for ARM64-based Systems", "4486996"}:                                                 "4487021",
	{"Windows 10 Version 1709 for x64-based Systems", "4486996"}:                                                   "4487021",
	{"Windows Server, Version 1709 (Server Core installation)", "4486996"}:                                         "4487021",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4487017"}:                              "4487029",
	{"Internet Explorer 11 on Windows 10 Version 1803 for ARM64-based Systems", "4487017"}:                         "4487029",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4487017"}:                           "4487029",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for 32-bit Systems", "4487017"}:                      "4487029",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for ARM64-based Systems", "4487017"}:                 "4487029",
	{"Microsoft .NET Framework 3.5 on Windows 10 Version 1803 for x64-based Systems", "4487017"}:                   "4487029",
	{"Microsoft .NET Framework 3.5 on Windows Server, Version 1803 (Server Core installation)", "4487017"}:         "4487029",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for 32-bit Systems", "4487017"}:                    "4487029",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for ARM64-based Systems", "4487017"}:               "4487029",
	{"Microsoft .NET Framework 4.7.2 on Windows 10 Version 1803 for x64-based Systems", "4487017"}:                 "4487029",
	{"Microsoft .NET Framework 4.7.2 on Windows Server, Version 1803 (Server Core installation)", "4487017"}:       "4487029",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4487017"}:                   "4487029",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for ARM64-based Systems", "4487017"}:              "4487029",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4487017"}:                "4487029",
	{"Windows 10 Version 1803 for 32-bit Systems", "4487017"}:                                                      "4487029",
	{"Windows 10 Version 1803 for ARM64-based Systems", "4487017"}:                                                 "4487029",
	{"Windows 10 Version 1803 for x64-based Systems", "4487017"}:                                                   "4487029",
	{"Windows Server, Version 1803 (Server Core installation)", "4487017"}:                                         "4487029",

	// 2019-Feb (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4486564"}:                                            "4486563",
	{"Windows 7 for x64-based Systems Service Pack 1", "4486564"}:                                         "4486563",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4486564"}:                        "4486563",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4486564"}:                            "4486563",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4486564"}: "4486563",
	{"Windows 8.1 for 32-bit Systems", "4487028"}:                                                         "4487000",
	{"Windows 8.1 for x64-based Systems", "4487028"}:                                                      "4487000",
	{"Windows Server 2012 R2", "4487028"}:                                                                 "4487000",
	{"Windows Server 2012 R2 (Server Core installation)", "4487028"}:                                      "4487000",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4487019"}:                                  "4487023",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4487019"}:       "4487023",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4487019"}:                           "4487023",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4487019"}:                               "4487023",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4487019"}:    "4487023",
	{"Windows Server 2012", "4486993"}:                                                                    "4487025",
	{"Windows Server 2012 (Server Core installation)", "4486993"}:                                         "4487025",

	// 2019-Mar (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4489871"}:                 "4489888",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4489871"}:              "4489888",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4489871"}:      "4489888",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4489871"}:   "4489888",
	{"Windows 10 Version 1703 for 32-bit Systems", "4489871"}:                                         "4489888",
	{"Windows 10 Version 1703 for x64-based Systems", "4489871"}:                                      "4489888",
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4489886"}:                 "4489890",
	{"Internet Explorer 11 on Windows 10 Version 1709 for ARM64-based Systems", "4489886"}:            "4489890",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4489886"}:              "4489890",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4489886"}:      "4489890",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for ARM64-based Systems", "4489886"}: "4489890",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4489886"}:   "4489890",
	{"Windows 10 Version 1709 for 32-bit Systems", "4489886"}:                                         "4489890",
	{"Windows 10 Version 1709 for ARM64-based Systems", "4489886"}:                                    "4489890",
	{"Windows 10 Version 1709 for x64-based Systems", "4489886"}:                                      "4489890",
	{"Windows Server, Version 1709 (Server Core installation)", "4489886"}:                            "4489890",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4489868"}:                 "4489894",
	{"Internet Explorer 11 on Windows 10 Version 1803 for ARM64-based Systems", "4489868"}:            "4489894",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4489868"}:              "4489894",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4489868"}:      "4489894",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for ARM64-based Systems", "4489868"}: "4489894",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4489868"}:   "4489894",
	{"Windows 10 Version 1803 for 32-bit Systems", "4489868"}:                                         "4489894",
	{"Windows 10 Version 1803 for ARM64-based Systems", "4489868"}:                                    "4489894",
	{"Windows 10 Version 1803 for x64-based Systems", "4489868"}:                                      "4489894",
	{"Windows Server, Version 1803 (Server Core installation)", "4489868"}:                            "4489894",

	// 2019-Mar (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4489885"}:                                            "4489878",
	{"Windows 7 for x64-based Systems Service Pack 1", "4489885"}:                                         "4489878",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4489885"}:                        "4489878",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4489885"}:                            "4489878",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4489885"}: "4489878",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4489876"}:                                  "4489880",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4489876"}:       "4489880",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4489876"}:                           "4489880",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4489876"}:                               "4489880",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4489876"}:    "4489880",
	{"Windows 8.1 for 32-bit Systems", "4489883"}:                                                         "4489881",
	{"Windows 8.1 for x64-based Systems", "4489883"}:                                                      "4489881",
	{"Windows Server 2012 R2", "4489883"}:                                                                 "4489881",
	{"Windows Server 2012 R2 (Server Core installation)", "4489883"}:                                      "4489881",
	{"Windows Server 2012", "4489884"}:                                                                    "4489891",
	{"Windows Server 2012 (Server Core installation)", "4489884"}:                                         "4489891",

	// 2019-Apr (Delta→Cumulative)
	{"Internet Explorer 11 on Windows 10 Version 1703 for 32-bit Systems", "4493474"}:                 "4493436",
	{"Internet Explorer 11 on Windows 10 Version 1703 for x64-based Systems", "4493474"}:              "4493436",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for 32-bit Systems", "4493474"}:      "4493436",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1703 for x64-based Systems", "4493474"}:   "4493436",
	{"Windows 10 Version 1703 for 32-bit Systems", "4493474"}:                                         "4493436",
	{"Windows 10 Version 1703 for x64-based Systems", "4493474"}:                                      "4493436",
	{"Internet Explorer 11 on Windows 10 Version 1803 for 32-bit Systems", "4493464"}:                 "4493437",
	{"Internet Explorer 11 on Windows 10 Version 1803 for ARM64-based Systems", "4493464"}:            "4493437",
	{"Internet Explorer 11 on Windows 10 Version 1803 for x64-based Systems", "4493464"}:              "4493437",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for 32-bit Systems", "4493464"}:      "4493437",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for ARM64-based Systems", "4493464"}: "4493437",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1803 for x64-based Systems", "4493464"}:   "4493437",
	{"Windows 10 Version 1803 for 32-bit Systems", "4493464"}:                                         "4493437",
	{"Windows 10 Version 1803 for ARM64-based Systems", "4493464"}:                                    "4493437",
	{"Windows 10 Version 1803 for x64-based Systems", "4493464"}:                                      "4493437",
	{"Windows Server, Version 1803 (Server Core installation)", "4493464"}:                            "4493437",
	{"Internet Explorer 11 on Windows 10 Version 1709 for 32-bit Systems", "4493441"}:                 "4493440",
	{"Internet Explorer 11 on Windows 10 Version 1709 for ARM64-based Systems", "4493441"}:            "4493440",
	{"Internet Explorer 11 on Windows 10 Version 1709 for x64-based Systems", "4493441"}:              "4493440",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for 32-bit Systems", "4493441"}:      "4493440",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for ARM64-based Systems", "4493441"}: "4493440",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1709 for x64-based Systems", "4493441"}:   "4493440",
	{"Windows 10 Version 1709 for 32-bit Systems", "4493441"}:                                         "4493440",
	{"Windows 10 Version 1709 for ARM64-based Systems", "4493441"}:                                    "4493440",
	{"Windows 10 Version 1709 for x64-based Systems", "4493441"}:                                      "4493440",
	{"Windows Server, Version 1709 (Server Core installation)", "4493441"}:                            "4493440",
	{"Internet Explorer 11 on Windows 10 Version 1607 for 32-bit Systems", "4493470"}:                 "4499418",
	{"Internet Explorer 11 on Windows 10 Version 1607 for x64-based Systems", "4493470"}:              "4499418",
	{"Internet Explorer 11 on Windows Server 2016", "4493470"}:                                        "4499418",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for 32-bit Systems", "4493470"}:      "4499418",
	{"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems", "4493470"}:   "4499418",
	{"Microsoft Edge (EdgeHTML-based) on Windows Server 2016", "4493470"}:                             "4499418",
	{"Windows 10 Version 1607 for 32-bit Systems", "4493470"}:                                         "4499418",
	{"Windows 10 Version 1607 for x64-based Systems", "4493470"}:                                      "4499418",
	{"Windows Server 2016", "4493470"}:                                                                "4499418",
	{"Windows Server 2016 (Server Core installation)", "4493470"}:                                     "4499418",

	// 2019-Apr (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4493467"}:                                                         "4493446",
	{"Windows 8.1 for x64-based Systems", "4493467"}:                                                      "4493446",
	{"Windows Server 2012 R2", "4493467"}:                                                                 "4493446",
	{"Windows Server 2012 R2 (Server Core installation)", "4493467"}:                                      "4493446",
	{"Windows Server 2012", "4493450"}:                                                                    "4493451",
	{"Windows Server 2012 (Server Core installation)", "4493450"}:                                         "4493451",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4493458"}:                                  "4493471",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4493458"}:       "4493471",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4493458"}:                           "4493471",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4493458"}:                               "4493471",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4493458"}:    "4493471",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4493448"}:                                            "4493472",
	{"Windows 7 for x64-based Systems Service Pack 1", "4493448"}:                                         "4493472",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4493448"}:                        "4493472",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4493448"}:                            "4493472",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4493448"}: "4493472",

	// 2019-May (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4499180"}:                                  "4499149",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4499180"}:       "4499149",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4499180"}:                           "4499149",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4499180"}:                               "4499149",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4499180"}:    "4499149",
	{"Windows 8.1 for 32-bit Systems", "4499165"}:                                                         "4499151",
	{"Windows 8.1 for x64-based Systems", "4499165"}:                                                      "4499151",
	{"Windows Server 2012 R2", "4499165"}:                                                                 "4499151",
	{"Windows Server 2012 R2 (Server Core installation)", "4499165"}:                                      "4499151",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4499175"}:                                            "4499164",
	{"Windows 7 for x64-based Systems Service Pack 1", "4499175"}:                                         "4499164",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4499175"}:                        "4499164",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4499175"}:                            "4499164",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4499175"}: "4499164",
	{"Windows Server 2012", "4499158"}:                                                                    "4499171",
	{"Windows Server 2012 (Server Core installation)", "4499158"}:                                         "4499171",

	// 2019-Jun (SecurityOnly→MonthlyRollup)
	{"Internet Explorer 9 on Windows Server 2008 for x64-based Systems Service Pack 2", "4503287"}:        "4503273",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4503287"}:                                  "4503273",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4503287"}:       "4503273",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4503287"}:                           "4503273",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4503287"}:                               "4503273",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4503287"}:    "4503273",
	{"Windows 8.1 for 32-bit Systems", "4503290"}:                                                         "4503276",
	{"Windows 8.1 for x64-based Systems", "4503290"}:                                                      "4503276",
	{"Windows Server 2012 R2", "4503290"}:                                                                 "4503276",
	{"Windows Server 2012 R2 (Server Core installation)", "4503290"}:                                      "4503276",
	{"Windows Server 2012", "4503263"}:                                                                    "4503285",
	{"Windows Server 2012 (Server Core installation)", "4503263"}:                                         "4503285",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4503269"}:                                            "4503292",
	{"Windows 7 for x64-based Systems Service Pack 1", "4503269"}:                                         "4503292",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4503269"}:                        "4503292",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4503269"}:                            "4503292",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4503269"}: "4503292",

	// 2019-Jul (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4507457"}:                                                         "4507448",
	{"Windows 8.1 for x64-based Systems", "4507457"}:                                                      "4507448",
	{"Windows Server 2012 R2", "4507457"}:                                                                 "4507448",
	{"Windows Server 2012 R2 (Server Core installation)", "4507457"}:                                      "4507448",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4507456"}:                                            "4507449",
	{"Windows 7 for x64-based Systems Service Pack 1", "4507456"}:                                         "4507449",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4507456"}:                        "4507449",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4507456"}:                            "4507449",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4507456"}: "4507449",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4507461"}:                                  "4507452",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4507461"}:       "4507452",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4507461"}:                           "4507452",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4507461"}:                               "4507452",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4507461"}:    "4507452",
	{"Windows Server 2012", "4507464"}:                                                                    "4507462",
	{"Windows Server 2012 (Server Core installation)", "4507464"}:                                         "4507462",

	// 2019-Aug (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4512491"}:                                  "4512476",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4512491"}:       "4512476",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4512491"}:                           "4512476",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4512491"}:                               "4512476",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4512491"}:    "4512476",
	{"Windows 8.1 for 32-bit Systems", "4512489"}:                                                         "4512488",
	{"Windows 8.1 for x64-based Systems", "4512489"}:                                                      "4512488",
	{"Windows Server 2012 R2", "4512489"}:                                                                 "4512488",
	{"Windows Server 2012 R2 (Server Core installation)", "4512489"}:                                      "4512488",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4512486"}:                                            "4512506",
	{"Windows 7 for x64-based Systems Service Pack 1", "4512486"}:                                         "4512506",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4512486"}:                        "4512506",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4512486"}:                            "4512506",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4512486"}: "4512506",
	{"Windows Server 2012", "4512482"}:                                                                    "4512518",
	{"Windows Server 2012 (Server Core installation)", "4512482"}:                                         "4512518",

	// 2019-Sep (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4516051"}:                                  "4516026",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4516051"}:       "4516026",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4516051"}:                           "4516026",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4516051"}:                               "4516026",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4516051"}:    "4516026",
	{"Windows Server 2012", "4516062"}:                                                                    "4516055",
	{"Windows Server 2012 (Server Core installation)", "4516062"}:                                         "4516055",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4516033"}:                                            "4516065",
	{"Windows 7 for x64-based Systems Service Pack 1", "4516033"}:                                         "4516065",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4516033"}:                        "4516065",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4516033"}:                            "4516065",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4516033"}: "4516065",
	{"Windows 8.1 for 32-bit Systems", "4516064"}:                                                         "4516067",
	{"Windows 8.1 for x64-based Systems", "4516064"}:                                                      "4516067",
	{"Windows Server 2012 R2", "4516064"}:                                                                 "4516067",
	{"Windows Server 2012 R2 (Server Core installation)", "4516064"}:                                      "4516067",

	// 2019-Oct (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4520009"}:                                  "4520002",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4520009"}:       "4520002",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4520009"}:                           "4520002",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4520009"}:                               "4520002",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4520009"}:    "4520002",
	{"Windows 8.1 for 32-bit Systems", "4519990"}:                                                         "4520005",
	{"Windows 8.1 for x64-based Systems", "4519990"}:                                                      "4520005",
	{"Windows Server 2012 R2", "4519990"}:                                                                 "4520005",
	{"Windows Server 2012 R2 (Server Core installation)", "4519990"}:                                      "4520005",
	{"Windows Server 2012", "4519985"}:                                                                    "4524154",
	{"Windows Server 2012 (Server Core installation)", "4519985"}:                                         "4524154",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4520003"}:                                            "4524157",
	{"Windows 7 for x64-based Systems Service Pack 1", "4520003"}:                                         "4524157",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4520003"}:                        "4524157",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4520003"}:                            "4524157",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4520003"}: "4524157",

	// 2019-Nov (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4525239"}:                                  "4525234",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4525239"}:       "4525234",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4525239"}:                           "4525234",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4525239"}:                               "4525234",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4525239"}:    "4525234",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4525233"}:                                            "4525235",
	{"Windows 7 for x64-based Systems Service Pack 1", "4525233"}:                                         "4525235",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4525233"}:                        "4525235",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4525233"}:                            "4525235",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4525233"}: "4525235",
	{"Windows 8.1 for 32-bit Systems", "4525250"}:                                                         "4525243",
	{"Windows 8.1 for x64-based Systems", "4525250"}:                                                      "4525243",
	{"Windows Server 2012 R2", "4525250"}:                                                                 "4525243",
	{"Windows Server 2012 R2 (Server Core installation)", "4525250"}:                                      "4525243",
	{"Windows Server 2012", "4525253"}:                                                                    "4525246",
	{"Windows Server 2012 (Server Core installation)", "4525253"}:                                         "4525246",

	// 2019-Dec (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4530698"}:                                                                    "4530691",
	{"Windows Server 2012 (Server Core installation)", "4530698"}:                                         "4530691",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4530719"}:                                  "4530695",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4530719"}:       "4530695",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4530719"}:                           "4530695",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4530719"}:                               "4530695",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4530719"}:    "4530695",
	{"Windows 8.1 for 32-bit Systems", "4530730"}:                                                         "4530702",
	{"Windows 8.1 for x64-based Systems", "4530730"}:                                                      "4530702",
	{"Windows Server 2012 R2", "4530730"}:                                                                 "4530702",
	{"Windows Server 2012 R2 (Server Core installation)", "4530730"}:                                      "4530702",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4530692"}:                                            "4530734",
	{"Windows 7 for x64-based Systems Service Pack 1", "4530692"}:                                         "4530734",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4530692"}:                        "4530734",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4530692"}:                            "4530734",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4530692"}: "4530734",

	// 2020-Jan (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4534288"}:                                                                    "4534283",
	{"Windows Server 2012 (Server Core installation)", "4534288"}:                                         "4534283",
	{"Windows 8.1 for 32-bit Systems", "4534309"}:                                                         "4534297",
	{"Windows 8.1 for x64-based Systems", "4534309"}:                                                      "4534297",
	{"Windows Server 2012 R2", "4534309"}:                                                                 "4534297",
	{"Windows Server 2012 R2 (Server Core installation)", "4534309"}:                                      "4534297",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4534312"}:                                  "4534303",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4534312"}:       "4534303",
	{"Windows Server 2008 for Itanium-based Systems Service Pack 2", "4534312"}:                           "4534303",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4534312"}:                               "4534303",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4534312"}:    "4534303",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4534314"}:                                            "4534310",
	{"Windows 7 for x64-based Systems Service Pack 1", "4534314"}:                                         "4534310",
	{"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", "4534314"}:                        "4534310",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4534314"}:                            "4534310",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4534314"}: "4534310",

	// 2020-Feb (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4537822"}:                                  "4537810",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4537822"}:       "4537810",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4537822"}:                               "4537810",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4537822"}:    "4537810",
	{"Windows Server 2012", "4537794"}:                                                                    "4537814",
	{"Windows Server 2012 (Server Core installation)", "4537794"}:                                         "4537814",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4537813"}:                                            "4537820",
	{"Windows 7 for x64-based Systems Service Pack 1", "4537813"}:                                         "4537820",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4537813"}:                            "4537820",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4537813"}: "4537820",
	{"Windows 8.1 for 32-bit Systems", "4537803"}:                                                         "4537821",
	{"Windows 8.1 for x64-based Systems", "4537803"}:                                                      "4537821",
	{"Windows Server 2012 R2", "4537803"}:                                                                 "4537821",
	{"Windows Server 2012 R2 (Server Core installation)", "4537803"}:                                      "4537821",

	// 2020-Mar (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4541500"}:                                            "4540688",
	{"Windows 7 for x64-based Systems Service Pack 1", "4541500"}:                                         "4540688",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4541500"}:                            "4540688",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4541500"}: "4540688",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4541504"}:                                  "4541506",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4541504"}:       "4541506",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4541504"}:                               "4541506",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4541504"}:    "4541506",
	{"Windows 8.1 for 32-bit Systems", "4541505"}:                                                         "4541509",
	{"Windows 8.1 for x64-based Systems", "4541505"}:                                                      "4541509",
	{"Windows Server 2012 R2", "4541505"}:                                                                 "4541509",
	{"Windows Server 2012 R2 (Server Core installation)", "4541505"}:                                      "4541509",
	{"Windows Server 2012", "4540694"}:                                                                    "4541510",
	{"Windows Server 2012 (Server Core installation)", "4540694"}:                                         "4541510",

	// 2020-Apr (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4550971"}:                                                                    "4550917",
	{"Windows Server 2012 (Server Core installation)", "4550971"}:                                         "4550917",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4550957"}:                                  "4550951",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4550957"}:       "4550951",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4550957"}:                               "4550951",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4550957"}:    "4550951",
	{"Windows 8.1 for 32-bit Systems", "4550970"}:                                                         "4550961",
	{"Windows 8.1 for x64-based Systems", "4550970"}:                                                      "4550961",
	{"Windows Server 2012 R2", "4550970"}:                                                                 "4550961",
	{"Windows Server 2012 R2 (Server Core installation)", "4550970"}:                                      "4550961",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4550965"}:                                            "4550964",
	{"Windows 7 for x64-based Systems Service Pack 1", "4550965"}:                                         "4550964",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4550965"}:                            "4550964",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4550965"}: "4550964",

	// 2020-May (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4556843"}:                                            "4556836",
	{"Windows 7 for x64-based Systems Service Pack 1", "4556843"}:                                         "4556836",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4556843"}:                            "4556836",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4556843"}: "4556836",
	{"Windows Server 2012", "4556852"}:                                                                    "4556840",
	{"Windows Server 2012 (Server Core installation)", "4556852"}:                                         "4556840",
	{"Windows 8.1 for 32-bit Systems", "4556853"}:                                                         "4556846",
	{"Windows 8.1 for x64-based Systems", "4556853"}:                                                      "4556846",
	{"Windows Server 2012 R2", "4556853"}:                                                                 "4556846",
	{"Windows Server 2012 R2 (Server Core installation)", "4556853"}:                                      "4556846",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4556854"}:                                  "4556860",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4556854"}:       "4556860",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4556854"}:                               "4556860",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4556854"}:    "4556860",

	// 2020-Jun (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4561674"}:                                                                    "4561612",
	{"Windows Server 2012 (Server Core installation)", "4561674"}:                                         "4561612",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4561669"}:                                            "4561643",
	{"Windows 7 for x64-based Systems Service Pack 1", "4561669"}:                                         "4561643",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4561669"}:                            "4561643",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4561669"}: "4561643",
	{"Windows 8.1 for 32-bit Systems", "4561673"}:                                                         "4561666",
	{"Windows 8.1 for x64-based Systems", "4561673"}:                                                      "4561666",
	{"Windows Server 2012 R2", "4561673"}:                                                                 "4561666",
	{"Windows Server 2012 R2 (Server Core installation)", "4561673"}:                                      "4561666",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4561645"}:                                  "4561670",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4561645"}:       "4561670",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4561645"}:                               "4561670",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4561645"}:    "4561670",

	// 2020-Jul (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4565539"}:                                            "4565524",
	{"Windows 7 for x64-based Systems Service Pack 1", "4565539"}:                                         "4565524",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4565539"}:                            "4565524",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4565539"}: "4565524",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4565529"}:                                  "4565536",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4565529"}:       "4565536",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4565529"}:                               "4565536",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4565529"}:    "4565536",
	{"Windows Server 2012", "4565535"}:                                                                    "4565537",
	{"Windows Server 2012 (Server Core installation)", "4565535"}:                                         "4565537",
	{"Windows 8.1 for 32-bit Systems", "4565540"}:                                                         "4565541",
	{"Windows 8.1 for x64-based Systems", "4565540"}:                                                      "4565541",
	{"Windows Server 2012 R2", "4565540"}:                                                                 "4565541",
	{"Windows Server 2012 R2 (Server Core installation)", "4565540"}:                                      "4565541",

	// 2020-Aug (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "4571723"}:                                                         "4571703",
	{"Windows 8.1 for x64-based Systems", "4571723"}:                                                      "4571703",
	{"Windows Server 2012 R2", "4571723"}:                                                                 "4571703",
	{"Windows Server 2012 R2 (Server Core installation)", "4571723"}:                                      "4571703",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4571719"}:                                            "4571729",
	{"Windows 7 for x64-based Systems Service Pack 1", "4571719"}:                                         "4571729",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4571719"}:                            "4571729",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4571719"}: "4571729",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4571746"}:                                  "4571730",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4571746"}:       "4571730",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4571746"}:                               "4571730",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4571746"}:    "4571730",
	{"Windows Server 2012", "4571702"}:                                                                    "4571736",
	{"Windows Server 2012 (Server Core installation)", "4571702"}:                                         "4571736",

	// 2020-Sep (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4577048"}:                                                                    "4577038",
	{"Windows Server 2012 (Server Core installation)", "4577048"}:                                         "4577038",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4577053"}:                                            "4577051",
	{"Windows 7 for x64-based Systems Service Pack 1", "4577053"}:                                         "4577051",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4577053"}:                            "4577051",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4577053"}: "4577051",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4577070"}:                                  "4577064",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4577070"}:       "4577064",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4577070"}:                               "4577064",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4577070"}:    "4577064",
	{"Windows 8.1 for 32-bit Systems", "4577071"}:                                                         "4577066",
	{"Windows 8.1 for x64-based Systems", "4577071"}:                                                      "4577066",
	{"Windows Server 2012 R2", "4577071"}:                                                                 "4577066",
	{"Windows Server 2012 R2 (Server Core installation)", "4577071"}:                                      "4577066",

	// 2020-Oct (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4580387"}:                                            "4580345",
	{"Windows 7 for x64-based Systems Service Pack 1", "4580387"}:                                         "4580345",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4580387"}:                            "4580345",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4580387"}: "4580345",
	{"Windows 8.1 for 32-bit Systems", "4580358"}:                                                         "4580347",
	{"Windows 8.1 for x64-based Systems", "4580358"}:                                                      "4580347",
	{"Windows Server 2012 R2", "4580358"}:                                                                 "4580347",
	{"Windows Server 2012 R2 (Server Core installation)", "4580358"}:                                      "4580347",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4580385"}:                                  "4580378",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4580385"}:       "4580378",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4580385"}:                               "4580378",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4580385"}:    "4580378",
	{"Windows Server 2012", "4580353"}:                                                                    "4580382",
	{"Windows Server 2012 (Server Core installation)", "4580353"}:                                         "4580382",

	// 2020-Nov (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4586817"}:                                  "4586807",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4586817"}:       "4586807",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4586817"}:                               "4586807",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4586817"}:    "4586807",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4586805"}:                                            "4586827",
	{"Windows 7 for x64-based Systems Service Pack 1", "4586805"}:                                         "4586827",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4586805"}:                            "4586827",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4586805"}: "4586827",
	{"Windows Server 2012", "4586808"}:                                                                    "4586834",
	{"Windows Server 2012 (Server Core installation)", "4586808"}:                                         "4586834",
	{"Windows 8.1 for 32-bit Systems", "4586823"}:                                                         "4586845",
	{"Windows 8.1 for x64-based Systems", "4586823"}:                                                      "4586845",
	{"Windows Server 2012 R2", "4586823"}:                                                                 "4586845",
	{"Windows Server 2012 R2 (Server Core installation)", "4586823"}:                                      "4586845",

	// 2020-Dec (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4592497"}:                                                                    "4592468",
	{"Windows Server 2012 (Server Core installation)", "4592497"}:                                         "4592468",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4592503"}:                                            "4592471",
	{"Windows 7 for x64-based Systems Service Pack 1", "4592503"}:                                         "4592471",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4592503"}:                            "4592471",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4592503"}: "4592471",
	{"Windows 8.1 for 32-bit Systems", "4592495"}:                                                         "4592484",
	{"Windows 8.1 for x64-based Systems", "4592495"}:                                                      "4592484",
	{"Windows Server 2012 R2", "4592495"}:                                                                 "4592484",
	{"Windows Server 2012 R2 (Server Core installation)", "4592495"}:                                      "4592484",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4592504"}:                                  "4592498",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4592504"}:       "4592498",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4592504"}:                               "4592498",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4592504"}:    "4592498",

	// 2021-Jan (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "4598297"}:                                                                    "4598278",
	{"Windows Server 2012 (Server Core installation)", "4598297"}:                                         "4598278",
	{"Windows 7 for 32-bit Systems Service Pack 1", "4598289"}:                                            "4598279",
	{"Windows 7 for x64-based Systems Service Pack 1", "4598289"}:                                         "4598279",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4598289"}:                            "4598279",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4598289"}: "4598279",
	{"Windows 8.1 for 32-bit Systems", "4598275"}:                                                         "4598285",
	{"Windows 8.1 for x64-based Systems", "4598275"}:                                                      "4598285",
	{"Windows Server 2012 R2", "4598275"}:                                                                 "4598285",
	{"Windows Server 2012 R2 (Server Core installation)", "4598275"}:                                      "4598285",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4598287"}:                                  "4598288",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4598287"}:       "4598288",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4598287"}:                               "4598288",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4598287"}:    "4598288",

	// 2021-Feb (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "4601363"}:                                            "4601347",
	{"Windows 7 for x64-based Systems Service Pack 1", "4601363"}:                                         "4601347",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "4601363"}:                            "4601347",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "4601363"}: "4601347",
	{"Windows Server 2012", "4601357"}:                                                                    "4601348",
	{"Windows Server 2012 (Server Core installation)", "4601357"}:                                         "4601348",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "4601366"}:                                  "4601360",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "4601366"}:       "4601360",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "4601366"}:                               "4601360",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "4601366"}:    "4601360",
	{"Windows 8.1 for 32-bit Systems", "4601349"}:                                                         "4601384",
	{"Windows 8.1 for x64-based Systems", "4601349"}:                                                      "4601384",
	{"Windows Server 2012 R2", "4601349"}:                                                                 "4601384",
	{"Windows Server 2012 R2 (Server Core installation)", "4601349"}:                                      "4601384",

	// 2021-Mar (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5000851"}:                                            "5000841",
	{"Windows 7 for x64-based Systems Service Pack 1", "5000851"}:                                         "5000841",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5000851"}:                            "5000841",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5000851"}: "5000841",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5000856"}:                                  "5000844",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5000856"}:       "5000844",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5000856"}:                               "5000844",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5000856"}:    "5000844",
	{"Windows Server 2012", "5000840"}:                                                                    "5000847",
	{"Windows Server 2012 (Server Core installation)", "5000840"}:                                         "5000847",
	{"Windows 8.1 for 32-bit Systems", "5000853"}:                                                         "5000848",
	{"Windows 8.1 for x64-based Systems", "5000853"}:                                                      "5000848",
	{"Windows Server 2012 R2", "5000853"}:                                                                 "5000848",
	{"Windows Server 2012 R2 (Server Core installation)", "5000853"}:                                      "5000848",

	// 2021-Apr (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5001392"}:                                            "5001335",
	{"Windows 7 for x64-based Systems Service Pack 1", "5001392"}:                                         "5001335",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5001392"}:                            "5001335",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5001392"}: "5001335",
	{"Windows 8.1 for 32-bit Systems", "5001393"}:                                                         "5001382",
	{"Windows 8.1 for x64-based Systems", "5001393"}:                                                      "5001382",
	{"Windows Server 2012 R2", "5001393"}:                                                                 "5001382",
	{"Windows Server 2012 R2 (Server Core installation)", "5001393"}:                                      "5001382",
	{"Windows Server 2012", "5001383"}:                                                                    "5001387",
	{"Windows Server 2012 (Server Core installation)", "5001383"}:                                         "5001387",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5001332"}:                                  "5001389",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5001332"}:       "5001389",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5001332"}:                               "5001389",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5001332"}:    "5001389",

	// 2021-May (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "5003203"}:                                                                    "5003208",
	{"Windows Server 2012 (Server Core installation)", "5003203"}:                                         "5003208",
	{"Windows 8.1 for 32-bit Systems", "5003220"}:                                                         "5003209",
	{"Windows 8.1 for x64-based Systems", "5003220"}:                                                      "5003209",
	{"Windows Server 2012 R2", "5003220"}:                                                                 "5003209",
	{"Windows Server 2012 R2 (Server Core installation)", "5003220"}:                                      "5003209",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5003225"}:                                  "5003210",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5003225"}:       "5003210",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5003225"}:                               "5003210",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5003225"}:    "5003210",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5003228"}:                                            "5003233",
	{"Windows 7 for x64-based Systems Service Pack 1", "5003228"}:                                         "5003233",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5003228"}:                            "5003233",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5003228"}: "5003233",

	// 2021-Jun (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5003695"}:                                  "5003661",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5003695"}:       "5003661",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5003695"}:                               "5003661",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5003695"}:    "5003661",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5003694"}:                                            "5003667",
	{"Windows 7 for x64-based Systems Service Pack 1", "5003694"}:                                         "5003667",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5003694"}:                            "5003667",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5003694"}: "5003667",
	{"Windows 8.1 for 32-bit Systems", "5003681"}:                                                         "5003671",
	{"Windows 8.1 for x64-based Systems", "5003681"}:                                                      "5003671",
	{"Windows Server 2012 R2", "5003681"}:                                                                 "5003671",
	{"Windows Server 2012 R2 (Server Core installation)", "5003681"}:                                      "5003671",
	{"Windows Server 2012", "5003696"}:                                                                    "5003697",
	{"Windows Server 2012 (Server Core installation)", "5003696"}:                                         "5003697",

	// 2021-Jul (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5004307"}:                                            "5004289",
	{"Windows 7 for x64-based Systems Service Pack 1", "5004307"}:                                         "5004289",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5004307"}:                            "5004289",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5004307"}: "5004289",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5004951"}:                            "5004289",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5004951"}: "5004289",
	{"Windows 8.1 for 32-bit Systems", "5004285"}:                                                         "5004954",
	{"Windows 8.1 for x64-based Systems", "5004285"}:                                                      "5004954",
	{"Windows Server 2012 R2", "5004285"}:                                                                 "5004954",
	{"Windows Server 2012 R2 (Server Core installation)", "5004285"}:                                      "5004954",
	{"Windows Server 2012 R2", "5004958"}:                                                                 "5004954",
	{"Windows Server 2012 R2 (Server Core installation)", "5004958"}:                                      "5004954",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5004299"}:                                  "5004955",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5004299"}:       "5004955",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5004299"}:                               "5004955",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5004299"}:    "5004955",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5004959"}:                                  "5004955",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5004959"}:       "5004955",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5004959"}:                               "5004955",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5004959"}:    "5004955",
	{"Windows Server 2012", "5004302"}:                                                                    "5004956",
	{"Windows Server 2012 (Server Core installation)", "5004302"}:                                         "5004956",
	{"Windows Server 2012", "5004960"}:                                                                    "5004956",
	{"Windows Server 2012 (Server Core installation)", "5004960"}:                                         "5004956",

	// 2021-Aug (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "5005106"}:                                                         "5005076",
	{"Windows 8.1 for x64-based Systems", "5005106"}:                                                      "5005076",
	{"Windows Server 2012 R2", "5005106"}:                                                                 "5005076",
	{"Windows Server 2012 R2 (Server Core installation)", "5005106"}:                                      "5005076",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5005089"}:                                            "5005088",
	{"Windows 7 for x64-based Systems Service Pack 1", "5005089"}:                                         "5005088",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5005089"}:                            "5005088",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5005089"}: "5005088",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5005095"}:                                  "5005090",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5005095"}:       "5005090",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5005095"}:                               "5005090",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5005095"}:    "5005090",
	{"Windows Server 2012", "5005094"}:                                                                    "5005099",
	{"Windows Server 2012 (Server Core installation)", "5005094"}:                                         "5005099",

	// 2021-Sep (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5005618"}:                                  "5005606",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5005618"}:       "5005606",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5005618"}:                               "5005606",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5005618"}:    "5005606",
	{"Windows 8.1 for 32-bit Systems", "5005627"}:                                                         "5005613",
	{"Windows 8.1 for x64-based Systems", "5005627"}:                                                      "5005613",
	{"Windows Server 2012 R2", "5005627"}:                                                                 "5005613",
	{"Windows Server 2012 R2 (Server Core installation)", "5005627"}:                                      "5005613",
	{"Windows Server 2012", "5005607"}:                                                                    "5005623",
	{"Windows Server 2012 (Server Core installation)", "5005607"}:                                         "5005623",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5005615"}:                                            "5005633",
	{"Windows 7 for x64-based Systems Service Pack 1", "5005615"}:                                         "5005633",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5005615"}:                            "5005633",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5005615"}: "5005633",

	// 2021-Oct (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "5006729"}:                                                         "5006714",
	{"Windows 8.1 for x64-based Systems", "5006729"}:                                                      "5006714",
	{"Windows Server 2012 R2", "5006729"}:                                                                 "5006714",
	{"Windows Server 2012 R2 (Server Core installation)", "5006729"}:                                      "5006714",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5006715"}:                                  "5006736",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5006715"}:       "5006736",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5006715"}:                               "5006736",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5006715"}:    "5006736",
	{"Windows Server 2012", "5006732"}:                                                                    "5006739",
	{"Windows Server 2012 (Server Core installation)", "5006732"}:                                         "5006739",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5006728"}:                                            "5006743",
	{"Windows 7 for x64-based Systems Service Pack 1", "5006728"}:                                         "5006743",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5006728"}:                            "5006743",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5006728"}: "5006743",

	// 2021-Nov (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5007233"}:                                            "5007236",
	{"Windows 7 for x64-based Systems Service Pack 1", "5007233"}:                                         "5007236",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5007233"}:                            "5007236",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5007233"}: "5007236",
	{"Windows 8.1 for 32-bit Systems", "5007255"}:                                                         "5007247",
	{"Windows 8.1 for x64-based Systems", "5007255"}:                                                      "5007247",
	{"Windows Server 2012 R2", "5007255"}:                                                                 "5007247",
	{"Windows Server 2012 R2 (Server Core installation)", "5007255"}:                                      "5007247",
	{"Windows Server 2012", "5007245"}:                                                                    "5007260",
	{"Windows Server 2012 (Server Core installation)", "5007245"}:                                         "5007260",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5007246"}:                                  "5007263",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5007246"}:       "5007263",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5007246"}:                               "5007263",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5007246"}:    "5007263",

	// 2021-Dec (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5008282"}:                                            "5008244",
	{"Windows 7 for x64-based Systems Service Pack 1", "5008282"}:                                         "5008244",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5008282"}:                            "5008244",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5008282"}: "5008244",
	{"Windows 8.1 for 32-bit Systems", "5008285"}:                                                         "5008263",
	{"Windows 8.1 for x64-based Systems", "5008285"}:                                                      "5008263",
	{"Windows Server 2012 R2", "5008285"}:                                                                 "5008263",
	{"Windows Server 2012 R2 (Server Core installation)", "5008285"}:                                      "5008263",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5008271"}:                                  "5008274",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5008271"}:       "5008274",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5008271"}:                               "5008274",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5008271"}:    "5008274",
	{"Windows Server 2012", "5008255"}:                                                                    "5008277",
	{"Windows Server 2012 (Server Core installation)", "5008255"}:                                         "5008277",

	// 2022-Jan (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "5009619"}:                                                                    "5009586",
	{"Windows Server 2012 (Server Core installation)", "5009619"}:                                         "5009586",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5009621"}:                                            "5009610",
	{"Windows 7 for x64-based Systems Service Pack 1", "5009621"}:                                         "5009610",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5009621"}:                            "5009610",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5009621"}: "5009610",
	{"Windows 8.1 for 32-bit Systems", "5009595"}:                                                         "5009624",
	{"Windows 8.1 for x64-based Systems", "5009595"}:                                                      "5009624",
	{"Windows Server 2012 R2", "5009595"}:                                                                 "5009624",
	{"Windows Server 2012 R2 (Server Core installation)", "5009595"}:                                      "5009624",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5009601"}:                                  "5009627",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5009601"}:       "5009627",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5009601"}:                               "5009627",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5009601"}:    "5009627",

	// 2022-Feb (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5010403"}:                                  "5010384",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5010403"}:       "5010384",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5010403"}:                               "5010384",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5010403"}:    "5010384",
	{"Windows Server 2012", "5010412"}:                                                                    "5010392",
	{"Windows Server 2012 (Server Core installation)", "5010412"}:                                         "5010392",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5010422"}:                                            "5010404",
	{"Windows 7 for x64-based Systems Service Pack 1", "5010422"}:                                         "5010404",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5010422"}:                            "5010404",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5010422"}: "5010404",
	{"Windows 8.1 for 32-bit Systems", "5010395"}:                                                         "5010419",
	{"Windows 8.1 for x64-based Systems", "5010395"}:                                                      "5010419",
	{"Windows Server 2012 R2", "5010395"}:                                                                 "5010419",
	{"Windows Server 2012 R2 (Server Core installation)", "5010395"}:                                      "5010419",

	// 2022-Mar (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5011525"}:                                  "5011534",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5011525"}:       "5011534",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5011525"}:                               "5011534",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5011525"}:    "5011534",
	{"Windows Server 2012", "5011527"}:                                                                    "5011535",
	{"Windows Server 2012 (Server Core installation)", "5011527"}:                                         "5011535",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5011529"}:                                            "5011552",
	{"Windows 7 for x64-based Systems Service Pack 1", "5011529"}:                                         "5011552",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5011529"}:                            "5011552",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5011529"}: "5011552",
	{"Windows 8.1 for 32-bit Systems", "5011560"}:                                                         "5011564",
	{"Windows 8.1 for x64-based Systems", "5011560"}:                                                      "5011564",
	{"Windows Server 2012 R2", "5011560"}:                                                                 "5011564",
	{"Windows Server 2012 R2 (Server Core installation)", "5011560"}:                                      "5011564",

	// 2022-Apr (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5012649"}:                                            "5012626",
	{"Windows 7 for x64-based Systems Service Pack 1", "5012649"}:                                         "5012626",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5012649"}:                            "5012626",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5012649"}: "5012626",
	{"Windows Server 2012", "5012666"}:                                                                    "5012650",
	{"Windows Server 2012 (Server Core installation)", "5012666"}:                                         "5012650",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5012632"}:                                  "5012658",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5012632"}:       "5012658",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5012632"}:                               "5012658",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5012632"}:    "5012658",
	{"Windows 8.1 for 32-bit Systems", "5012639"}:                                                         "5012670",
	{"Windows 8.1 for x64-based Systems", "5012639"}:                                                      "5012670",
	{"Windows Server 2012 R2", "5012639"}:                                                                 "5012670",
	{"Windows Server 2012 R2 (Server Core installation)", "5012639"}:                                      "5012670",

	// 2022-May (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5014006"}:                                  "5014010",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5014006"}:       "5014010",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5014006"}:                               "5014010",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5014006"}:    "5014010",
	{"Windows 8.1 for 32-bit Systems", "5014001"}:                                                         "5014011",
	{"Windows 8.1 for x64-based Systems", "5014001"}:                                                      "5014011",
	{"Windows Server 2012 R2", "5014001"}:                                                                 "5014011",
	{"Windows Server 2012 R2 (Server Core installation)", "5014001"}:                                      "5014011",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5013999"}:                                            "5014012",
	{"Windows 7 for x64-based Systems Service Pack 1", "5013999"}:                                         "5014012",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5013999"}:                            "5014012",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5013999"}: "5014012",
	{"Windows Server 2012", "5014018"}:                                                                    "5014017",
	{"Windows Server 2012 (Server Core installation)", "5014018"}:                                         "5014017",

	// 2022-Jun (SecurityOnly→MonthlyRollup)
	{"Windows 8.1 for 32-bit Systems", "5014746"}:                                                         "5014738",
	{"Windows 8.1 for x64-based Systems", "5014746"}:                                                      "5014738",
	{"Windows Server 2012 R2", "5014746"}:                                                                 "5014738",
	{"Windows Server 2012 R2 (Server Core installation)", "5014746"}:                                      "5014738",
	{"Windows Server 2012", "5014741"}:                                                                    "5014747",
	{"Windows Server 2012 (Server Core installation)", "5014741"}:                                         "5014747",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5014742"}:                                            "5014748",
	{"Windows 7 for x64-based Systems Service Pack 1", "5014742"}:                                         "5014748",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5014742"}:                            "5014748",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5014742"}: "5014748",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5014743"}:                                  "5014752",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5014743"}:       "5014752",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5014743"}:                               "5014752",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5014743"}:    "5014752",

	// 2022-Jul (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5015862"}:                                            "5015861",
	{"Windows 7 for x64-based Systems Service Pack 1", "5015862"}:                                         "5015861",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5015862"}:                            "5015861",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5015862"}: "5015861",
	{"Windows Server 2012", "5015875"}:                                                                    "5015863",
	{"Windows Server 2012 (Server Core installation)", "5015875"}:                                         "5015863",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5015870"}:                                  "5015866",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5015870"}:       "5015866",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5015870"}:                               "5015866",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5015870"}:    "5015866",
	{"Windows 8.1 for 32-bit Systems", "5015877"}:                                                         "5015874",
	{"Windows 8.1 for x64-based Systems", "5015877"}:                                                      "5015874",
	{"Windows Server 2012 R2", "5015877"}:                                                                 "5015874",
	{"Windows Server 2012 R2 (Server Core installation)", "5015877"}:                                      "5015874",

	// 2022-Aug (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5016686"}:                                  "5016669",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5016686"}:       "5016669",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5016686"}:                               "5016669",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5016686"}:    "5016669",
	{"Windows Server 2012", "5016684"}:                                                                    "5016672",
	{"Windows Server 2012 (Server Core installation)", "5016684"}:                                         "5016672",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5016679"}:                                            "5016676",
	{"Windows 7 for x64-based Systems Service Pack 1", "5016679"}:                                         "5016676",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5016679"}:                            "5016676",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5016679"}: "5016676",
	{"Windows 8.1 for 32-bit Systems", "5016683"}:                                                         "5016681",
	{"Windows 8.1 for x64-based Systems", "5016683"}:                                                      "5016681",
	{"Windows Server 2012 R2", "5016683"}:                                                                 "5016681",
	{"Windows Server 2012 R2 (Server Core installation)", "5016683"}:                                      "5016681",

	// 2022-Sep (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5017371"}:                                  "5017358",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5017371"}:       "5017358",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5017371"}:                               "5017358",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5017371"}:    "5017358",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5017373"}:                                            "5017361",
	{"Windows 7 for x64-based Systems Service Pack 1", "5017373"}:                                         "5017361",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5017373"}:                            "5017361",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5017373"}: "5017361",
	{"Windows 8.1 for 32-bit Systems", "5017365"}:                                                         "5017367",
	{"Windows 8.1 for x64-based Systems", "5017365"}:                                                      "5017367",
	{"Windows Server 2012 R2", "5017365"}:                                                                 "5017367",
	{"Windows Server 2012 R2 (Server Core installation)", "5017365"}:                                      "5017367",
	{"Windows Server 2012", "5017377"}:                                                                    "5017370",
	{"Windows Server 2012 (Server Core installation)", "5017377"}:                                         "5017370",

	// 2022-Oct (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5018446"}:                                  "5018450",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5018446"}:       "5018450",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5018446"}:                               "5018450",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5018446"}:    "5018450",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5018479"}:                                            "5018454",
	{"Windows 7 for x64-based Systems Service Pack 1", "5018479"}:                                         "5018454",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5018479"}:                            "5018454",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5018479"}: "5018454",
	{"Windows Server 2012", "5018478"}:                                                                    "5018457",
	{"Windows Server 2012 (Server Core installation)", "5018478"}:                                         "5018457",
	{"Windows 8.1 for 32-bit Systems", "5018476"}:                                                         "5018474",
	{"Windows 8.1 for x64-based Systems", "5018476"}:                                                      "5018474",
	{"Windows Server 2012 R2", "5018476"}:                                                                 "5018474",
	{"Windows Server 2012 R2 (Server Core installation)", "5018476"}:                                      "5018474",

	// 2022-Nov (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5020013"}:                                            "5020000",
	{"Windows 7 for x64-based Systems Service Pack 1", "5020013"}:                                         "5020000",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5020013"}:                            "5020000",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5020013"}: "5020000",
	{"Windows Server 2012", "5020003"}:                                                                    "5020009",
	{"Windows Server 2012 (Server Core installation)", "5020003"}:                                         "5020009",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5020005"}:                                  "5020019",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5020005"}:       "5020019",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5020005"}:                               "5020019",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5020005"}:    "5020019",
	{"Windows 8.1 for 32-bit Systems", "5020010"}:                                                         "5020023",
	{"Windows 8.1 for x64-based Systems", "5020010"}:                                                      "5020023",
	{"Windows RT 8.1", "5020010"}:                                                                         "5020023",
	{"Windows Server 2012 R2", "5020010"}:                                                                 "5020023",
	{"Windows Server 2012 R2 (Server Core installation)", "5020010"}:                                      "5020023",

	// 2022-Dec (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "5021303"}:                                                                    "5021285",
	{"Windows Server 2012 (Server Core installation)", "5021303"}:                                         "5021285",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5021293"}:                                  "5021289",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5021293"}:       "5021289",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5021293"}:                               "5021289",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5021293"}:    "5021289",
	{"Windows 7 for 32-bit Systems Service Pack 1", "5021288"}:                                            "5021291",
	{"Windows 7 for x64-based Systems Service Pack 1", "5021288"}:                                         "5021291",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5021288"}:                            "5021291",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5021288"}: "5021291",
	{"Windows 8.1 for 32-bit Systems", "5021296"}:                                                         "5021294",
	{"Windows 8.1 for x64-based Systems", "5021296"}:                                                      "5021294",
	{"Windows Server 2012 R2", "5021296"}:                                                                 "5021294",
	{"Windows Server 2012 R2 (Server Core installation)", "5021296"}:                                      "5021294",

	// 2023-Jan (SecurityOnly→MonthlyRollup)
	{"Windows 7 for 32-bit Systems Service Pack 1", "5022339"}:                                            "5022338",
	{"Windows 7 for x64-based Systems Service Pack 1", "5022339"}:                                         "5022338",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5022339"}:                            "5022338",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5022339"}: "5022338",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5022353"}:                                  "5022340",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5022353"}:       "5022340",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5022353"}:                               "5022340",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5022353"}:    "5022340",
	{"Windows Server 2012", "5022343"}:                                                                    "5022348",
	{"Windows Server 2012 (Server Core installation)", "5022343"}:                                         "5022348",
	{"Windows 8.1 for 32-bit Systems", "5022346"}:                                                         "5022352",
	{"Windows 8.1 for x64-based Systems", "5022346"}:                                                      "5022352",
	{"Windows RT 8.1", "5022346"}:                                                                         "5022352",
	{"Windows Server 2012 R2", "5022346"}:                                                                 "5022352",
	{"Windows Server 2012 R2 (Server Core installation)", "5022346"}:                                      "5022352",

	// 2023-Feb (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5022874"}:                            "5022872",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5022874"}: "5022872",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5022893"}:                                  "5022890",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5022893"}:       "5022890",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5022893"}:                               "5022890",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5022893"}:    "5022890",
	{"Windows Server 2012 R2", "5022894"}:                                                                 "5022899",
	{"Windows Server 2012 R2 (Server Core installation)", "5022894"}:                                      "5022899",
	{"Windows Server 2012", "5022895"}:                                                                    "5022903",
	{"Windows Server 2012 (Server Core installation)", "5022895"}:                                         "5022903",

	// 2023-Mar (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5023754"}:                                  "5023755",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5023754"}:       "5023755",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5023754"}:                               "5023755",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5023754"}:    "5023755",
	{"Windows Server 2012", "5023752"}:                                                                    "5023756",
	{"Windows Server 2012 (Server Core installation)", "5023752"}:                                         "5023756",
	{"Windows Server 2012 R2", "5023764"}:                                                                 "5023765",
	{"Windows Server 2012 R2 (Server Core installation)", "5023764"}:                                      "5023765",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5023759"}:                            "5023769",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5023759"}: "5023769",

	// 2023-Apr (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5025273"}:                                  "5025271",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5025273"}:       "5025271",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5025273"}:                               "5025271",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5025273"}:    "5025271",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5025277"}:                            "5025279",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5025277"}: "5025279",
	{"Windows Server 2012 R2", "5025288"}:                                                                 "5025285",
	{"Windows Server 2012 R2 (Server Core installation)", "5025288"}:                                      "5025285",
	{"Windows Server 2012", "5025272"}:                                                                    "5025287",
	{"Windows Server 2012 (Server Core installation)", "5025272"}:                                         "5025287",

	// 2023-May (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5026427"}:                                  "5026408",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5026427"}:       "5026408",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5026427"}:                               "5026408",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5026427"}:    "5026408",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5026426"}:                            "5026413",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5026426"}: "5026413",
	{"Windows Server 2012 R2", "5026409"}:                                                                 "5026415",
	{"Windows Server 2012 R2 (Server Core installation)", "5026409"}:                                      "5026415",
	{"Windows Server 2012", "5026411"}:                                                                    "5026419",
	{"Windows Server 2012 (Server Core installation)", "5026411"}:                                         "5026419",

	// 2023-Jun (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012 R2", "5027282"}:                                                                 "5027271",
	{"Windows Server 2012 R2 (Server Core installation)", "5027282"}:                                      "5027271",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5027256"}:                            "5027275",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5027256"}: "5027275",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5027277"}:                                  "5027279",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5027277"}:       "5027279",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5027277"}:                               "5027279",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5027277"}:    "5027279",
	{"Windows Server 2012", "5027281"}:                                                                    "5027283",
	{"Windows Server 2012 (Server Core installation)", "5027281"}:                                         "5027283",

	// 2023-Jul (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5028226"}:                                  "5028222",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5028226"}:       "5028222",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5028226"}:                               "5028222",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5028226"}:    "5028222",
	{"Windows Server 2012 R2", "5028223"}:                                                                 "5028228",
	{"Windows Server 2012 R2 (Server Core installation)", "5028223"}:                                      "5028228",
	{"Windows Server 2012", "5028233"}:                                                                    "5028232",
	{"Windows Server 2012 (Server Core installation)", "5028233"}:                                         "5028232",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5028224"}:                            "5028240",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5028224"}: "5028240",

	// 2023-Aug (SecurityOnly→MonthlyRollup)
	{"Windows Server 2012", "5029308"}:                                                                    "5029295",
	{"Windows Server 2012 (Server Core installation)", "5029308"}:                                         "5029295",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5029307"}:                            "5029296",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5029307"}: "5029296",
	{"Windows Server 2012 R2", "5029304"}:                                                                 "5029312",
	{"Windows Server 2012 R2 (Server Core installation)", "5029304"}:                                      "5029312",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5029301"}:                                  "5029318",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5029301"}:       "5029318",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5029301"}:                               "5029318",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5029301"}:    "5029318",

	// 2023-Sep (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5030261"}:                            "5030265",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5030261"}: "5030265",
	{"Windows Server 2012 R2", "5030287"}:                                                                 "5030269",
	{"Windows Server 2012 R2 (Server Core installation)", "5030287"}:                                      "5030269",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5030286"}:                                  "5030271",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5030286"}:       "5030271",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5030286"}:                               "5030271",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5030286"}:    "5030271",
	{"Windows Server 2012", "5030279"}:                                                                    "5030278",
	{"Windows Server 2012 (Server Core installation)", "5030279"}:                                         "5030278",

	// 2023-Oct (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5031441"}:                            "5031408",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5031441"}: "5031408",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5031411"}:                                  "5031416",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5031411"}:       "5031416",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5031411"}:                               "5031416",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5031411"}:    "5031416",
	{"Windows Server 2012 R2", "5031407"}:                                                                 "5031419",
	{"Windows Server 2012 R2 (Server Core installation)", "5031407"}:                                      "5031419",
	{"Windows Server 2012", "5031427"}:                                                                    "5031442",
	{"Windows Server 2012 (Server Core installation)", "5031427"}:                                         "5031442",

	// 2023-Nov (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5032250"}:                            "5032252",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5032250"}: "5032252",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5032248"}:                                  "5032254",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5032248"}:       "5032254",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5032248"}:                               "5032254",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5032248"}:    "5032254",

	// 2023-Dec (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5033427"}:                                  "5033422",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5033427"}:       "5033422",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5033427"}:                               "5033422",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5033427"}:    "5033422",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5033424"}:                            "5033433",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5033424"}: "5033433",

	// 2024-Jan (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5034167"}:                            "5034169",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5034167"}: "5034169",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2", "5034176"}:                                  "5034173",
	{"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", "5034176"}:       "5034173",
	{"Windows Server 2008 for x64-based Systems Service Pack 2", "5034176"}:                               "5034173",
	{"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", "5034176"}:    "5034173",

	// 2024-Apr (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5036922"}:                            "5036967",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5036922"}: "5036967",

	// 2024-Aug (SecurityOnly→MonthlyRollup)
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1", "5041823"}:                            "5041838",
	{"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", "5041823"}: "5041838",
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

			// Register the twin KB (Cumulative / Monthly Rollup counterpart of
			// a chain-less Delta / Security Only KB) so its Products list also
			// includes this product. The twin is referenced as an additional KB
			// criterion in buildDetections; ensuring its Products entry is
			// populated keeps detection-time product filtering consistent.
			if twinKBID, ok := kbCumulativeTwins[[2]string{criterionProductName, kbID}]; ok {
				tkb := kbm[twinKBID]
				if tkb.KBID == "" {
					tkb.KBID = twinKBID
					tkb.URL = fmt.Sprintf("https://support.microsoft.com/help/%s", twinKBID)
					tkb.DataSource = sourceTypes.Source{
						ID:   sourceTypes.MicrosoftCVRF,
						Raws: e.r.Paths(),
					}
				}
				if !slices.Contains(tkb.Products, criterionProductName) {
					tkb.Products = append(tkb.Products, criterionProductName)
				}
				kbm[twinKBID] = tkb
			}

			// Supercedence may list multiple KBs separated by commas or semicolons.
			// Comma-separated (e.g. "5017500, 5018858, 5018545") is common for .NET Framework products.
			// Semicolon-separated (e.g. "3181707; 3203838") appears in older (2016-2017) data.
			// Mixed formats (e.g. "MS16-016, 3124280; MS16-097, 3178034") also exist;
			// non-digit tokens (bulletin IDs) are filtered out by the isAllDigits check below.
			var supKBIDs []string
			for semiPart := range strings.SplitSeq(r.Supercedence, ";") {
				for commaPart := range strings.SplitSeq(semiPart, ",") {
					supKBIDs = append(supKBIDs, strings.TrimSpace(commaPart))
				}
			}
			for _, supKBID := range supKBIDs {
				if !isAllDigits(supKBID) {
					continue
				}

				skb := kbm[supKBID]
				if skb.KBID == "" {
					skb.KBID = supKBID
					skb.URL = fmt.Sprintf("https://support.microsoft.com/help/%s", supKBID)
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
				kbm[supKBID] = skb
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
