package bulletin

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	windowskbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb"
	windowskbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/supersededby"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/bulletin"
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
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "bulletin"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Bulletin")

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

		var rows []bulletin.Bulletin
		if err := e.r.Read(path, e.inputDir, &rows); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}
		if len(rows) == 0 {
			return nil
		}

		datas, kbs, err := e.extract(rows)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		for _, data := range datas {
			splitted, err := util.Split(strings.TrimPrefix(strings.ToLower(string(data.ID)), "ms"), "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "MS<yy>-<nnn>", data.ID)
			}
			if _, err := time.Parse("06", splitted[0]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "MS<yy>-<nnn>", data.ID)
			}

			if err := util.Write(filepath.Join(options.dir, "data", splitted[0], fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[0], fmt.Sprintf("%s.json", data.ID)))
			}
		}

		for _, kb := range kbs {
			if kb.KBID == "" {
				return errors.Errorf("unexpected empty KBID. path: %q", path)
			}

			if len(kb.KBID) <= 3 {
				return errors.Errorf("unexpected KBID format. expected: len > 3, actual: %q, path: %q", kb.KBID, path)
			}

			filename := filepath.Join(options.dir, "windowskb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID))
			if _, err := os.Stat(filename); err == nil {
				if err := func() error {
					f, err := os.Open(filename)
					if err != nil {
						return errors.Wrapf(err, "open %s", filename)
					}
					defer f.Close()

					var base windowskbTypes.KB
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
		ID:   sourceTypes.MicrosoftBulletin,
		Name: func() *string { s := "Microsoft Security Bulletin"; return &s }(),
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

var dateLocalePrefix = regexp.MustCompile(`^\[\$-[0-9a-fA-F]+\]`)

// parseCVEs parses CVE identifiers from the raw cves field.
// The raw data is historical and frozen, so all anomalous patterns are enumerated explicitly.
func parseCVEs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}

	var cves []string
	for token := range strings.SplitSeq(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		switch {
		// Standard format: CVE-YYYY-NNNN or CAN-YYYY-NNNN
		case strings.HasPrefix(token, "CVE-") || strings.HasPrefix(token, "CAN-"):
			// e.g. "CVE-2016-7254\n" -> trim trailing control characters
			token = strings.TrimSpace(token)

			switch {
			// "CVE-CVE-2007-0515" -> "CVE-2007-0515"
			case strings.HasPrefix(token, "CVE-CVE-"):
				cves = append(cves, fmt.Sprintf("CVE-%s", strings.TrimPrefix(token, "CVE-CVE-")))

			// "CVE-2015-2442CVE-2015-2446" -> two CVEs concatenated without comma
			case strings.Contains(token, "CVE-") && strings.Count(token, "CVE-") >= 2:
				for part := range strings.SplitSeq(token, "CVE-") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					cves = append(cves, fmt.Sprintf("CVE-%s", part))
				}

			default:
				cves = append(cves, token)
			}

		// "CVE- 2007-3028" -> "CVE-2007-3028" (space after dash)
		case strings.HasPrefix(token, "CVE- "):
			cves = append(cves, fmt.Sprintf("CVE-%s", strings.TrimPrefix(token, "CVE- ")))

		// "CVE 2007-0029" -> "CVE-2007-0029" (space instead of dash)
		case strings.HasPrefix(token, "CVE "):
			cves = append(cves, fmt.Sprintf("CVE-%s", strings.TrimPrefix(token, "CVE ")))

		// "CVE20163247" -> "CVE-2016-3247" (no separators)
		case strings.HasPrefix(token, "CVE") && len(token) >= 11 && token[3] >= '0' && token[3] <= '9':
			cves = append(cves, fmt.Sprintf("CVE-%s-%s", token[3:7], token[7:]))

		// "2008-1438" -> "CVE-2008-1438" (missing prefix)
		case token[0] >= '0' && token[0] <= '9' && strings.Contains(token, "-"):
			cves = append(cves, fmt.Sprintf("CVE-%s", token))

		// lowercase: "cve-2012-0159" -> "CVE-2012-0159"
		case strings.HasPrefix(token, "cve-"):
			cves = append(cves, fmt.Sprintf("CVE-%s", strings.TrimPrefix(token, "cve-")))

		// bare "CVE" (truncated, no ID) -> skip
		case token == "CVE":
			continue

		default:
			return nil, errors.Errorf("unexpected CVE format: %q", token)
		}
	}
	return cves, nil
}

// parseSupersedes extracts superseded KB IDs from the Supersedes field.
// Known formats in the historical data:
//   - Single entry:             "MS17-005[4010250]"          → ["4010250"]
//   - Comma-separated entries:  "MS03-026[823980],MS03-039[824146]" → ["823980", "824146"]
//   - Semicolon-separated KBs:  "MS03-013[881493;811493]"    → ["881493", "811493"]
//   - No brackets (ID only):    "MS00-006"                   → [] (skipped)
func parseSupersedes(raw string) []string {
	if raw == "" {
		return nil
	}

	var kbIDs []string
	// Split by "," to handle comma-separated entries (e.g. "MS03-026[823980],MS03-039[824146]")
	for entry := range strings.SplitSeq(raw, ",") {
		// Extract content inside brackets (e.g. "MS17-005[4010250]" → "4010250")
		open := strings.Index(entry, "[")
		close := strings.Index(entry, "]")
		if open < 0 || close <= open+1 {
			// No brackets or empty brackets (e.g. "MS00-006") → skip
			continue
		}
		inner := entry[open+1 : close]

		// Split by ";" to handle multiple KBs inside one bracket (e.g. "881493;811493")
		for kbID := range strings.SplitSeq(inner, ";") {
			kbID = strings.TrimSpace(kbID)
			if kbID != "" {
				kbIDs = append(kbIDs, kbID)
			}
		}
	}
	return kbIDs
}

// productName builds a product name from the affected product and component fields.
// The format aligns with microsoft-cvrf's fullproductname convention:
//   - If one side is a Windows OS or SharePoint Server platform, the name is "<app> on <platform>"
//   - Otherwise, the component name alone is used (e.g., "Microsoft Word 2010 SP2")
func productName(product, component string) string {
	if component == "" || component == product {
		return product
	}
	switch {
	case isOSPlatform(component):
		return fmt.Sprintf("%s on %s", product, component)
	case isOSPlatform(product):
		return fmt.Sprintf("%s on %s", component, product)
	default:
		return component
	}
}

// isOSPlatform reports whether s is a Windows OS, SharePoint Server, or similar platform name.
func isOSPlatform(s string) bool {
	s = strings.TrimPrefix(s, "Microsoft ")
	switch {
	case strings.HasPrefix(s, "Windows "):
		rest := s[len("Windows "):]
		if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			return true
		}
		return strings.HasPrefix(rest, "Server") ||
			strings.HasPrefix(rest, "Vista") ||
			strings.HasPrefix(rest, "XP") ||
			strings.HasPrefix(rest, "RT") ||
			strings.HasPrefix(rest, "NT ") ||
			strings.HasPrefix(rest, "Millennium") ||
			strings.HasPrefix(rest, "ME") ||
			strings.HasPrefix(rest, "Home Server") ||
			strings.HasPrefix(rest, "Small Business Server") ||
			strings.HasPrefix(rest, "Embedded")
	case strings.Contains(strings.ToLower(s), "sharepoint server"):
		return true
	default:
		return false
	}
}

func (e extractor) extract(rows []bulletin.Bulletin) ([]dataTypes.Data, []windowskbTypes.KB, error) {
	type dataGroup struct {
		advisories []advisoryTypes.Advisory
		vulns      []vulnerabilityTypes.Vulnerability
		conditions []conditionTypes.Condition
	}

	groups := make(map[dataTypes.RootID]dataGroup)
	kbProducts := make(map[string]map[string]struct{})
	kbSupersededBy := make(map[string]map[string]struct{}) // old KBID → set of new KBIDs

	for _, row := range rows {
		if row.AffectedProduct == "" {
			switch strings.ToUpper(row.BulletinID) {
			case "MS01-002", "MS01-050":
				continue
			default:
				return nil, nil, errors.Errorf("unexpected empty affected_product. bulletin_id: %q", row.BulletinID)
			}
		}

		ids, err := parseCVEs(row.CVEs)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "parse CVEs. bulletin_id: %q, cves: %q", row.BulletinID, row.CVEs)
		}

		rootID := dataTypes.RootID(strings.ToUpper(row.BulletinID))
		splitted, err := util.Split(strings.TrimPrefix(string(rootID), "MS"), "-")
		if err != nil {
			return nil, nil, errors.Errorf("unexpected bulletin_id format. expected: %q, actual: %q", "MS<yy>-<nnn>", rootID)
		}
		if _, err := time.Parse("06", splitted[0]); err != nil {
			return nil, nil, errors.Errorf("unexpected bulletin_id format. expected: %q, actual: %q", "MS<yy>-<nnn>", rootID)
		}

		pn := productName(row.AffectedProduct, row.AffectedComponent)

		seg := segmentTypes.Segment{
			Ecosystem: ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeMicrosoft),
			Tag:       segmentTypes.DetectionTag(pn),
		}

		g := groups[rootID]

		// Advisory: dedup by content, merge segments
		ac := advisoryContentTypes.Content{
			ID:    advisoryContentTypes.AdvisoryID(rootID),
			Title: row.Title,
			Severity: func() []severityTypes.Severity {
				if row.Severity != "" {
					return []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "security@microsoft.com",
						Vendor: new(row.Severity),
					}}
				}
				if row.BulletinSeverity != "" {
					return []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "security@microsoft.com",
						Vendor: new(row.BulletinSeverity),
					}}
				}
				return nil
			}(),
			References: []referenceTypes.Reference{{
				Source: "security@microsoft.com",
				URL:    fmt.Sprintf("https://learn.microsoft.com/en-us/security-updates/securitybulletins/20%s/%s", rootID[2:4], strings.ToLower(string(rootID))),
			}},
			Published: utiltime.Parse([]string{"1/2/2006", "01/02/2006", "01-02-06", "2006-01-02"}, dateLocalePrefix.ReplaceAllString(row.DatePosted, "")),
			Optional: func() map[string]any {
				if row.BulletinImpact != "" {
					return map[string]any{"impact": row.BulletinImpact}
				}
				return nil
			}(),
		}
		switch idx := slices.IndexFunc(g.advisories, func(a advisoryTypes.Advisory) bool {
			return advisoryContentTypes.Compare(a.Content, ac) == 0
		}); idx {
		case -1:
			g.advisories = append(g.advisories, advisoryTypes.Advisory{
				Content:  ac,
				Segments: []segmentTypes.Segment{seg},
			})
		default:
			if !slices.ContainsFunc(g.advisories[idx].Segments, func(s segmentTypes.Segment) bool {
				return segmentTypes.Compare(s, seg) == 0
			}) {
				g.advisories[idx].Segments = append(g.advisories[idx].Segments, seg)
			}
		}

		// Vulnerabilities: dedup by content, merge segments
		for _, cve := range ids {
			vc := vulnerabilityContentTypes.Content{
				ID: vulnerabilityContentTypes.VulnerabilityID(cve),
				References: []referenceTypes.Reference{{
					Source: "security@microsoft.com",
					URL:    fmt.Sprintf("https://msrc.microsoft.com/update-guide/vulnerability/%s", cve),
				}},
			}

			switch idx := slices.IndexFunc(g.vulns, func(v vulnerabilityTypes.Vulnerability) bool {
				return vulnerabilityContentTypes.Compare(v.Content, vc) == 0
			}); idx {
			case -1:
				g.vulns = append(g.vulns, vulnerabilityTypes.Vulnerability{
					Content:  vc,
					Segments: []segmentTypes.Segment{seg},
				})
			default:
				if !slices.ContainsFunc(g.vulns[idx].Segments, func(s segmentTypes.Segment) bool {
					return segmentTypes.Compare(s, seg) == 0
				}) {
					g.vulns[idx].Segments = append(g.vulns[idx].Segments, seg)
				}
			}
		}

		// Conditions: dedup by tag, dedup criterions by KBID
		if row.ComponentKB != "" {
			cn := criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeKB,
				KB:   &kbcTypes.Criterion{Product: pn, KBID: row.ComponentKB},
			}

			switch idx := slices.IndexFunc(g.conditions, func(c conditionTypes.Condition) bool {
				return c.Tag == segmentTypes.DetectionTag(pn)
			}); idx {
			case -1:
				g.conditions = append(g.conditions, conditionTypes.Condition{
					Criteria: criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: []criterionTypes.Criterion{cn}},
					Tag:      segmentTypes.DetectionTag(pn),
				})
			default:
				if !slices.ContainsFunc(g.conditions[idx].Criteria.Criterions, func(e criterionTypes.Criterion) bool {
					return e.KB != nil && e.KB.KBID == row.ComponentKB
				}) {
					g.conditions[idx].Criteria.Criterions = append(g.conditions[idx].Criteria.Criterions, cn)
				}
			}

			if _, ok := kbProducts[row.ComponentKB]; !ok {
				kbProducts[row.ComponentKB] = make(map[string]struct{})
			}
			kbProducts[row.ComponentKB][pn] = struct{}{}

			for _, oldKBID := range parseSupersedes(row.Supersedes) {
				if _, ok := kbSupersededBy[oldKBID]; !ok {
					kbSupersededBy[oldKBID] = make(map[string]struct{})
				}
				kbSupersededBy[oldKBID][row.ComponentKB] = struct{}{}
			}
		}

		groups[rootID] = g
	}

	// Build result
	datas := make([]dataTypes.Data, 0, len(groups))
	for rootID, g := range groups {
		datas = append(datas, dataTypes.Data{
			ID:              rootID,
			Advisories:      g.advisories,
			Vulnerabilities: g.vulns,
			Detections: func() []detectionTypes.Detection {
				if len(g.conditions) == 0 {
					return nil
				}
				return []detectionTypes.Detection{{
					Ecosystem:  ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeMicrosoft),
					Conditions: g.conditions,
				}}
			}(),
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftBulletin,
				Raws: e.r.Paths(),
			},
		})
	}

	// WindowsKB entries
	kbs := make([]windowskbTypes.KB, 0, len(kbProducts)+len(kbSupersededBy))
	for kbID, products := range kbProducts {
		kb := windowskbTypes.KB{
			KBID:     kbID,
			Products: slices.Collect(maps.Keys(products)),
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftBulletin,
				Raws: e.r.Paths(),
			},
		}
		if newKBIDs, ok := kbSupersededBy[kbID]; ok {
			for newKBID := range newKBIDs {
				kb.SupersededBy = append(kb.SupersededBy, windowskbSupersededByTypes.SupersededBy{KBID: newKBID})
			}
			delete(kbSupersededBy, kbID)
		}
		kbs = append(kbs, kb)
	}
	for oldKBID, newKBIDs := range kbSupersededBy {
		ss := make([]windowskbSupersededByTypes.SupersededBy, 0, len(newKBIDs))
		for newKBID := range newKBIDs {
			ss = append(ss, windowskbSupersededByTypes.SupersededBy{KBID: newKBID})
		}
		kbs = append(kbs, windowskbTypes.KB{
			KBID:         oldKBID,
			SupersededBy: ss,
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftBulletin,
				Raws: e.r.Paths(),
			},
		})
	}

	return datas, kbs, nil
}
