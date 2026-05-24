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

	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
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
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
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

// normalizeArchiveComponentKey maps a bulletin row's (bulletin_id, affected_product,
// affected_component) tuple to a stable key used by bulletinArchiveComponentNotApplicable.
// The key matches the column-header form of the archive markdown's per-vulnerability
// severity table for the bulletin.
//
// Two vocabularies coexist:
//
//   - A bulletin-agnostic IE/Edge vocabulary for IE Cumulative bulletins, one
//     key per IE version: "Internet Explorer 6", "Internet Explorer 7",
//     "Internet Explorer 8", "Internet Explorer 9", "Internet Explorer 10",
//     "Internet Explorer 11", "Internet Explorer 11 on Windows 10", and
//     "Microsoft Edge".
//   - Per-bulletin product vocabularies for a small set of pre-IE-Cumulative
//     bulletins (MS06-012, MS06-020, MS06-039, MS06-078) where each
//     bulletin's markdown table uses its own column-header product strings,
//     taken verbatim from the bulletin. MS06-060 is handled by KB-keyed
//     entries instead — its Works Suite rows have affected_component=null
//     and cannot be matched by a component-keyed narrowing alone.
//
// Returns "" when the row does not map to any narrowing key (the common case;
// most rows have no NA narrowing on the component axis).
//
// The accepted input variants are enumerated explicitly rather than parsed, since
// BulletinSearch.xlsx uses a small, frozen vocabulary for each bulletin. The
// archive markdown's column-header vocabulary differs from the canonical names
// produced by microsoftutil.NormalizeProductName, so the two normalizers are
// intentionally kept independent.
func normalizeArchiveComponentKey(bulletinID, affectedProduct, affectedComponent string) string {
	product := strings.Join(strings.Fields(affectedProduct), " ")
	component := strings.Join(strings.Fields(affectedComponent), " ")

	// Dispatch by bulletin_id. Each MS06-* case uses its own product vocabulary
	// (matched against affected_product or affected_component depending on which
	// column the Excel side carries the identity in). MS17-006 has its own
	// case because the MS17 era swapped the IE/OS columns relative to MS14-MS16
	// (see the case below). The default case handles the remaining IE Cumulative
	// bulletins (MS14-* through MS16-*) via the shared IE/Edge global
	// vocabulary. Verified that no MS06-* bulletin in this dispatch has IE/Edge
	// rows in BulletinSearch.xlsx, so the default branch is unreachable for
	// the listed bulletins by design.
	switch bulletinID {
	case "MS06-012":
		// markdown columns bundle Word/Excel/Outlook/etc.; only the two PowerPoint
		// columns carry NA cells, so only those rows need a narrowing key.
		switch component {
		case "Microsoft PowerPoint 2000 Service Pack 3":
			return "Microsoft PowerPoint 2000"
		case "Microsoft PowerPoint 2002 Service Pack 3":
			return "Microsoft PowerPoint 2002"
		default:
			return ""
		}
	case "MS06-020":
		// The markdown table marks CVE-2005-2628 and CVE-2006-0024 NA on the
		// Win 2000 / Server 2003 / Server 2003 SP1 columns. BulletinSearch.xlsx
		// does not list rows for those product strings in the current corpus
		// (only Win 98 / 98 SE / ME and Win XP variants are present), so these
		// cases do not activate in practice. They are kept for completeness so
		// the map reflects the markdown data faithfully.
		switch product {
		case "Microsoft Windows 2000", "Microsoft Windows 2000 Service Pack 4":
			return "Windows 2000"
		case "Microsoft Windows Server 2003":
			return "Windows Server 2003"
		case "Microsoft Windows Server 2003 Service Pack 1":
			return "Windows Server 2003 Service Pack 1"
		default:
			return ""
		}
	case "MS06-039":
		switch product {
		case "Microsoft Project 2000":
			return "Microsoft Project 2000"
		default:
			return ""
		}
	// MS06-060 is handled by KB-keyed entries — see the comment at the top
	// of bulletinArchiveKBNotApplicable for KB923088/923089/923090/924998/
	// 924999. The component-keyed switch is intentionally absent because
	// some xlsx rows (Works Suite 2004/2005/2006) have affected_component=
	// null and cannot be matched by a component-keyed narrowing alone.
	case "MS06-078":
		switch component {
		case "Microsoft Windows Media Player 6.4":
			return "Windows Media Player 6.4 (All operating systems)"
		default:
			return ""
		}
	case "MS17-006":
		// MS17-006 (and likely the wider MS17 era) swaps the columns relative
		// to MS14-MS16: IE identity lives in affected_product, OS lives in
		// affected_component.
		return ieEdgeComponentKey(product, component)
	// Mixed-applicability bulletins where a KB is shared across multiple
	// xlsx rows whose per-CVE matrix cells differ in NA status: the same
	// (KB, CVE) pair is "Not applicable" for some product rows and
	// "Critical"/"Important"/etc. for others. This shape covers two
	// generator-side variants:
	//
	//   - Single-table mixed: the differing cells live in the same
	//     per-CVE matrix table at different product rows. The common
	//     case — e.g. MS16-106 / KB3185911 / CVE-2016-3349 is "Not
	//     affected" on the Vista/Server 2008/Win 7/Server 2008 R2 rows
	//     of the bulletin's single OS-rows × CVE-cols matrix table but
	//     "Important Elevation of Privilege" on the Win 8.1+ rows.
	//   - Multi-table mixed: the KB appears in more than one per-CVE
	//     matrix table of the same bulletin (e.g. an OS-only table and
	//     a .NET Framework component table). See the multi-table
	//     discussion below.
	//
	// In both variants a KB-keyed filter would over-broadly drop the
	// applicable rows too, so the NA cells are encoded product-keyed in
	// bulletinArchiveComponentNotApplicable; the dispatch here returns
	// the row's affected_product (whitespace-normalized at the top of
	// this function via strings.Fields/Join) so the inner key matches
	// the markdown's matrix table row[0] product label after the same
	// whitespace collapse.
	//
	// None of these bulletins have IE/Edge rows (they are Office /
	// Windows kernel / Graphics / etc.), so the IE/Edge default-branch
	// dispatch is not needed for them.
	//
	// Five of these bulletins (MS15-097, MS15-128, MS16-107, MS16-133,
	// MS17-018) fall into the multi-table-mixed variant: a KB appears
	// in multiple per-CVE matrix tables of the same bulletin. Whether
	// that creates an unfilterable FP is a per-(KB, CVE) question, not
	// a per-KB one: if a specific (KB, CVE) pair only appears in one of
	// those tables, product-keyed dispatch is still safe for that pair
	// (the conflicting cells live under different CVE columns and
	// therefore can't disagree with each other). The generator emits
	// product-keyed entries only for the safe pairs and silently drops
	// any pair whose markdown cells truly span tables with conflicting
	// NA state. The one such pair across the corpus (MS15-128 /
	// KB3116869 / CVE-2015-6108) is recovered by bulletinArchiveAmendments
	// (RowSplits field) — see that record's doc comment.
	case "MS08-033", "MS08-036", "MS08-037", "MS08-039",
		"MS09-001", "MS09-006", "MS09-008", "MS09-010", "MS09-012", "MS09-013", "MS09-022", "MS09-025", "MS09-039", "MS09-043", "MS09-044", "MS09-048", "MS09-058", "MS09-062", "MS09-065", "MS09-071",
		"MS10-006", "MS10-012", "MS10-015", "MS10-020", "MS10-021", "MS10-032", "MS10-034", "MS10-047", "MS10-048", "MS10-049", "MS10-054", "MS10-058", "MS10-073", "MS10-079", "MS10-088", "MS10-098",
		"MS11-011", "MS11-012", "MS11-015", "MS11-027", "MS11-036", "MS11-042", "MS11-054", "MS11-056", "MS11-058", "MS11-064", "MS11-074", "MS11-077", "MS11-090",
		"MS12-004", "MS12-009", "MS12-020", "MS12-032", "MS12-041", "MS12-050", "MS12-054", "MS12-074", "MS12-075",
		"MS13-016", "MS13-031", "MS13-036", "MS13-046", "MS13-063", "MS13-067", "MS13-076", "MS13-081", "MS13-091", "MS13-101",
		"MS14-028", "MS14-044",
		"MS15-023", "MS15-025", "MS15-064", "MS15-070", "MS15-073", "MS15-097", "MS15-101", "MS15-103", "MS15-111", "MS15-118", "MS15-128",
		"MS16-010", "MS16-014", "MS16-015", "MS16-045", "MS16-062", "MS16-067", "MS16-088", "MS16-090", "MS16-097", "MS16-099", "MS16-106", "MS16-107", "MS16-108", "MS16-111", "MS16-133", "MS16-135", "MS16-148",
		"MS17-012", "MS17-013", "MS17-014", "MS17-017", "MS17-018":
		return product
	// Pre-MS14 IE Cumulative bulletins: markdown column-header labels
	// combine the IE version and OS into a single string (e.g.
	// "Internet Explorer 6 for Windows XP Service Pack 3"). Use the
	// ieCumCombinedKey helper to construct the matching canonical
	// "IE_X for OS" key from the xlsx (component, product) pair.
	case "MS07-069",
		"MS08-031", "MS08-058", "MS08-073",
		"MS09-014", "MS09-019", "MS09-034", "MS09-054", "MS09-072",
		"MS10-002", "MS10-018", "MS10-035", "MS10-053", "MS10-071", "MS10-090",
		"MS11-003", "MS11-018", "MS11-050", "MS11-057", "MS11-081", "MS11-099",
		"MS12-010", "MS12-023", "MS12-037", "MS12-052", "MS12-063", "MS12-077",
		"MS13-009", "MS13-021", "MS13-037", "MS13-047", "MS13-055", "MS13-059", "MS13-069", "MS13-080", "MS13-088", "MS13-097":
		return ieCumCombinedKey(component, product)
	default:
		// MS14-* through MS16-* IE Cumulative layout: IE identity in
		// affected_component, OS in affected_product.
		if key := ieEdgeComponentKey(component, product); key != "" {
			return key
		}
		return ""
	}
}

// ieCumStripVersionDotZero strips the ".0" minor-version suffix from
// "Internet Explorer X.0" identifiers (so xlsx-form "Internet Explorer 6.0"
// matches the markdown-form "Internet Explorer 6" used in Format B labels).
// Leaves multi-digit minor versions like "Internet Explorer 5.01" alone.
var ieCumStripVersionDotZero = regexp.MustCompile(`Internet Explorer (\d+)\.0(\s|$)`)

// ieCumCombinedKey returns the canonical "Internet Explorer X (Service Pack Y) for OS"
// key form used by pre-MS14 IE Cumulative bulletins' Component-Drop entries.
// The markdown column-header labels for these bulletins combine the IE
// version and the OS into one column (e.g. "Internet Explorer 6 for
// Windows XP Service Pack 3"), with various connector words ("for", "on",
// "in", "when installed on") in the upstream markdown. Component-Drop
// keys store the connector as " for " uniformly; this function constructs
// the matching key from the xlsx row's (affected_component, affected_product)
// pair.
func ieCumCombinedKey(component, product string) string {
	if component == "" || product == "" {
		return ""
	}
	ie := strings.TrimPrefix(component, "Microsoft ")
	ie = strings.TrimPrefix(ie, "Windows ")
	if !strings.HasPrefix(ie, "Internet Explorer ") {
		return ""
	}
	ie = ieCumStripVersionDotZero.ReplaceAllString(ie, "Internet Explorer ${1}${2}")
	ie = strings.TrimSpace(ie)
	os := strings.TrimPrefix(product, "Microsoft ")
	return ie + " for " + os
}

// ieEdgeComponentKey maps an (IE/Edge identity, OS) tuple to the shared
// componentKey vocabulary used by bulletinArchiveComponentNotApplicable for
// IE Cumulative bulletins. Returns "" when ieField is not an IE/Edge string.
func ieEdgeComponentKey(ieField, osField string) string {
	switch ieField {
	case "Microsoft Edge":
		return "Microsoft Edge"
	case "Microsoft Internet Explorer 6.0", "Microsoft Internet Explorer 6.0 Service Pack 1":
		return "Internet Explorer 6"
	case "Windows Internet Explorer 7":
		return "Internet Explorer 7"
	case "Windows Internet Explorer 8":
		return "Internet Explorer 8"
	case "Internet Explorer 9", "Windows Internet Explorer 9":
		return "Internet Explorer 9"
	case "Internet Explorer 10", "Windows Internet Explorer 10":
		return "Internet Explorer 10"
	case "Internet Explorer 11", "Windows Internet Explorer 11":
		if strings.Contains(osField, "Windows 10") {
			return "Internet Explorer 11 on Windows 10"
		}
		return "Internet Explorer 11"
	default:
		return ""
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

// bulletinArchiveAmendment groups every static correction that an MSRC
// Bulletin contributes to the extracted dataset under a single per-bulletin
// record. Each field captures one axis of the correction, but all of them
// share the same scoping rule: an entry in MS-X's amendment only affects
// rows / chain edges that MS-X itself authored.
//
// Why per-bulletin? Earlier iterations spread these corrections across seven
// top-level maps (bulletinArchiveKBNotApplicable, *ComponentNotApplicable,
// *CVECorrections, *CVEAdditions, *ComponentReattribution, *Supersedes,
// *SupersedesOverride) keyed variously by KB / (bulletin, component) /
// bulletin / etc. Reviewing "what does MS17-006 change?" required grepping
// each map. Cross-bulletin influence was also implicit — a KB-keyed NA
// entry contributed by MS-A would silently apply to any other bulletin's
// row that happened to share the KB. Per-bulletin grouping makes the
// authorship explicit (each entry lives under the bulletin whose markdown
// documents it) and bounds the influence to that bulletin's rows at
// runtime.
//
// Runtime semantics:
//   - CVEAdjustments: applied to each row whose row.BulletinID matches the
//     map key. Each adjustment optionally narrows by KB and/or component
//     and then drops / adds / remaps CVE tokens.
//   - RowSplits: applied to each OS-only row (AffectedComponent == "") whose
//     (BulletinID, ComponentKB) matches a split entry. Listed CVEs move
//     from the source row to a synthesized (OS + component) row.
//   - Supersedes: per-(this bulletin's) KB add/override edges that are
//     merged into the global kbSupersededBy graph once after all xlsx rows
//     are processed.
//   - IECumChain: per-(this bulletin's) IE Cumulative chain edges. The
//     bulletin's amendment carries oldKBID → []newKBIDs where each newKBID
//     was released by this bulletin and supersedes oldKBID. Iterated once
//     globally across all bulletins to augment kbSupersededBy.
type bulletinArchiveAmendment struct {
	CVEAdjustments []cveAdjustment
	RowSplits      []rowSplit
	Supersedes     map[string]supersedesAdjust
	IECumChain     map[string][]string
}

// cveAdjustment selects rows of the owning bulletin by (optional KB,
// optional component) and rewrites their CVE list.
//
// Selector semantics:
//   - KB == "" matches any row.ComponentKB; KB != "" requires equality.
//   - Component == "" matches any row; Component != "" requires
//     normalizeArchiveComponentKey(row) == Component.
//   - When both fields are non-empty the row must satisfy both.
//   - When both are empty the adjustment applies to every row of the
//     owning bulletin.
//
// Action semantics (applied in this order when multiple fields are set):
//  1. Remap: for each CVE in row.CVEs, if Remap[token] != "" replace it
//     with the mapped value; if Remap[token] == "" the token is dropped.
//  2. Drop: remove any token listed here from row.CVEs.
//  3. Add: union the listed CVEs into row.CVEs.
//
// At most one of the three fields is populated in practice; combining
// them is supported but discouraged because it makes the entry harder to
// read.
type cveAdjustment struct {
	KB        string
	Component string
	Drop      []string
	Add       []string
	Remap     map[string]string
}

// rowSplit synthesizes a per-component row alongside the OS-only xlsx
// row it splits off from. It is applied only to rows where:
//
//	row.BulletinID == owning bulletin
//	row.ComponentKB == KB
//	row.AffectedComponent == ""    (OS-only row)
//
// The synthesized row carries the listed Component as affected_component
// and only the listed CVEs; the source row's CVE list has those CVEs
// removed.
type rowSplit struct {
	KB        string
	Component string
	CVEs      []string
}

// supersedesAdjust amends the supersedes edges for a single old KB — the
// Supersedes map key is always that old KB, and both fields list new KBs
// (the KBs that supersede it), i.e. members of the kbSupersededBy[oldKB] set:
//   - Add:      new KBs to union into kbSupersededBy[oldKB] — edges the
//     bulletin's archive markdown documents but BulletinSearch.xlsx omits.
//   - Override: new KBs to remove from kbSupersededBy[oldKB] — edges
//     BulletinSearch.xlsx incorrectly attributes to oldKB.
//
// Keeping the outer key consistently the old KB (rather than keying Override
// by the new KB) means one record reads as "for this old KB, add these
// superseders and drop those".
type supersedesAdjust struct {
	Add      []string
	Override []string
}

// bulletinArchiveAmendments is the single source of truth for static
// per-bulletin corrections to the extracted dataset. Entries are added
// incrementally by the migration that consolidates the legacy top-level
// amendment maps; once that migration completes, the legacy maps are
// removed.
var bulletinArchiveAmendments = map[string]bulletinArchiveAmendment{
	"MS02-019": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2002-0153"}}}},
	"MS02-038": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2002-0644", "CVE-2002-0645"}}}},
	"MS04-025": {
		IECumChain: map[string][]string{
			"832894": {"867801"},
		},
	},
	"MS04-038": {
		IECumChain: map[string][]string{
			"867801": {"834707"},
		},
	},
	"MS04-040": {
		IECumChain: map[string][]string{
			"834707": {"889293"},
		},
	},
	"MS05-020": {
		IECumChain: map[string][]string{
			"834707": {"890923"},
			"867801": {"890923"},
			"889293": {"890923"},
		},
	},
	"MS05-025": {
		IECumChain: map[string][]string{
			"889293": {"883939"},
			"890923": {"883939"},
		},
	},
	"MS05-038": {
		IECumChain: map[string][]string{
			"867801": {"896727"},
			"883939": {"896727"},
			"890923": {"896727"},
		},
	},
	"MS05-052": {
		IECumChain: map[string][]string{
			"896727": {"896688"},
		},
	},
	"MS05-054": {
		IECumChain: map[string][]string{
			"896688": {"905915"},
		},
	},
	"MS06-004": {
		IECumChain: map[string][]string{
			"905915": {"910620"},
		},
	},
	"MS06-007": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2006-0021"}}}},
	// MS06-012: year-typo of CVE-2005-4131 ("Excel eBay Vulnerability") —
	// remap (CVE-2005-4131 not in xlsx).
	"MS06-012": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft PowerPoint 2000", Drop: []string{"CVE-2005-4131", "CVE-2006-0028", "CVE-2006-0029", "CVE-2006-0030", "CVE-2006-0031"}},
			{Component: "Microsoft PowerPoint 2002", Drop: []string{"CVE-2005-4131", "CVE-2006-0028", "CVE-2006-0029", "CVE-2006-0030", "CVE-2006-0031"}},
			{Remap: map[string]string{"CVE-2006-4131": "CVE-2005-4131"}},
		},
	},
	"MS06-013": {
		IECumChain: map[string][]string{
			"905915": {"912812"},
			"910620": {"912812"},
		},
	},
	"MS06-015": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2004-2289", "CVE-2006-0012"}}}},
	"MS06-020": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 2000", Drop: []string{"CVE-2005-2628", "CVE-2006-0024"}},
			{Component: "Windows Server 2003", Drop: []string{"CVE-2005-2628", "CVE-2006-0024"}},
			{Component: "Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2005-2628", "CVE-2006-0024"}},
		},
	},
	// MS06-021: CVE-2006-4089 is a year-typo of CVE-2005-4089 ("CSS
	// Cross-Domain Information Disclosure") — remap (CVE-2005-4089 not in
	// xlsx). CVE-2006-2283 has no candidate in MS06-021's markdown — drop.
	"MS06-021": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2005-4089", "CVE-2006-1303", "CVE-2006-1626", "CVE-2006-1992", "CVE-2006-2218", "CVE-2006-2382", "CVE-2006-2383", "CVE-2006-2384", "CVE-2006-2385"}},
			{Remap: map[string]string{"CVE-2006-2283": "", "CVE-2006-4089": "CVE-2005-4089"}},
		},
		IECumChain: map[string][]string{
			"912812": {"916281"},
		},
	},
	"MS06-039": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2006-0007", "CVE-2006-0033"}},
			{Component: "Microsoft Project 2000", Drop: []string{"CVE-2006-0033"}},
		},
	},
	"MS06-042": {
		IECumChain: map[string][]string{
			"916281": {"918899"},
		},
	},
	"MS06-060": {
		CVEAdjustments: []cveAdjustment{
			{KB: "923088", Drop: []string{"CVE-2006-4693"}},
			{KB: "923089", Drop: []string{"CVE-2006-4693"}},
			{KB: "923090", Drop: []string{"CVE-2006-4693"}},
			{KB: "924998", Drop: []string{"CVE-2006-3651", "CVE-2006-4534"}},
			{KB: "924999", Drop: []string{"CVE-2006-3651", "CVE-2006-4534"}},
		},
	},
	"MS06-067": {
		IECumChain: map[string][]string{
			"918899": {"922760"},
		},
	},
	"MS06-078": {CVEAdjustments: []cveAdjustment{{Component: "Windows Media Player 6.4 (All operating systems)", Drop: []string{"CVE-2006-6134"}}}},
	"MS07-002": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-0027", "CVE-2007-0028", "CVE-2007-0029", "CVE-2007-0030", "CVE-2007-0031"}}}},
	"MS07-016": {
		IECumChain: map[string][]string{
			"922760": {"928090"},
		},
	},
	"MS07-027": {
		IECumChain: map[string][]string{
			"883939": {"931768"},
			"928090": {"931768"},
		},
	},
	"MS07-033": {
		IECumChain: map[string][]string{
			"931768": {"933566"},
		},
	},
	"MS07-039": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-0040", "CVE-2007-3028"}}}},
	// MS07-040 includes CVE-2006-7192 because the bulletin's V1.0 note
	// states the update "includes a defense-in-depth change to ASP.NET
	// ... mitigates the issue ... CVE-2006-7192". Mitigation rather
	// than full fix, but the KB is the only vehicle delivering the
	// protection.
	"MS07-040": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2006-7192", "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043"}}}},
	"MS07-045": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2007-0943", "CVE-2007-1891", "CVE-2007-1892", "CVE-2007-2216", "CVE-2007-3041"}},
		},
		IECumChain: map[string][]string{
			"933566": {"937143"},
		},
	},
	"MS07-057": {
		IECumChain: map[string][]string{
			"937143": {"939653"},
		},
	},
	"MS07-069": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2007-3902", "CVE-2007-3903", "CVE-2007-5344", "CVE-2007-5347"}},
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2007-3903", "CVE-2007-5344"}},
		},
		IECumChain: map[string][]string{
			"939653": {"942615"},
		},
	},
	"MS08-010": {
		IECumChain: map[string][]string{
			"883939": {"944533"},
			"890923": {"944533"},
			"942615": {"944533"},
		},
	},
	"MS08-024": {
		IECumChain: map[string][]string{
			"942615": {"947864"},
			"944533": {"947864"},
		},
	},
	"MS08-028": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2005-0944", "CVE-2007-6026"}}}},
	"MS08-029": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-1437", "CVE-2008-1438"}}}},
	"MS08-031": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-1442"}},
		},
		IECumChain: map[string][]string{
			"947864": {"950759"},
		},
	},
	"MS08-032": {
		IECumChain: map[string][]string{
			"3116869": {"3124266"},
			"3116900": {"3124263"},
			"3124263": {"3135173"},
			"3124266": {"3135174"},
		},
	},
	"MS08-033": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2008-1444"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2008-1444"}},
		},
	},
	"MS08-036": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-1440"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-1440"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2008-1440"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2008-1440"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2008-1440"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2008-1440"}},
		},
	},
	"MS08-037": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-1454"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-1454"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2008-1454"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2008-1454"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-1447"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-1447"}},
		},
	},
	"MS08-038": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-0951", "CVE-2008-1435"}}}},
	"MS08-039": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Exchange Server 2003 Service Pack 2", Drop: []string{"CVE-2008-2248"}},
			{Component: "Microsoft Exchange Server 2007", Drop: []string{"CVE-2008-2247"}},
			{Component: "Microsoft Exchange Server 2007 Service Pack 1", Drop: []string{"CVE-2008-2247"}},
		},
	},
	"MS08-040": {
		CVEAdjustments: []cveAdjustment{
			{KB: "941203", Drop: []string{"CVE-2008-0106"}},
			{KB: "948109", Drop: []string{"CVE-2008-0086"}},
			{KB: "948110", Drop: []string{"CVE-2008-0106"}},
			{KB: "948113", Drop: []string{"CVE-2008-0086", "CVE-2008-0106"}},
		},
	},
	"MS08-044": {CVEAdjustments: []cveAdjustment{{KB: "921598", Drop: []string{"CVE-2008-3020"}}}},
	"MS08-045": {
		IECumChain: map[string][]string{
			"950759": {"953838"},
		},
	},
	"MS08-051": {
		CVEAdjustments: []cveAdjustment{
			{KB: "949041", Drop: []string{"CVE-2008-1455"}},
			{KB: "949785", Drop: []string{"CVE-2008-0120", "CVE-2008-0121"}},
			{KB: "954038", Drop: []string{"CVE-2008-0120", "CVE-2008-0121"}},
			{KB: "956343", Drop: []string{"CVE-2008-0120", "CVE-2008-0121"}},
		},
	},
	"MS08-058": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2008-2947", "CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2008-3475", "CVE-2008-3476"}},
		},
		IECumChain: map[string][]string{
			"953838": {"956390"},
		},
	},
	"MS08-059": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-3466"}}}},
	"MS08-069": {
		CVEAdjustments: []cveAdjustment{
			{KB: "951535", Drop: []string{"CVE-2007-0099", "CVE-2008-4029"}},
			{KB: "951550", Drop: []string{"CVE-2007-0099", "CVE-2008-4029"}},
			{KB: "951597", Drop: []string{"CVE-2007-0099", "CVE-2008-4029"}},
			{KB: "954430", Drop: []string{"CVE-2007-0099"}},
			{KB: "954459", Drop: []string{"CVE-2007-0099", "CVE-2008-4029"}},
		},
	},
	"MS08-070": {
		CVEAdjustments: []cveAdjustment{
			{KB: "949045", Drop: []string{"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4254", "CVE-2008-4256"}},
			{KB: "949046", Drop: []string{"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254", "CVE-2008-4256"}},
			{KB: "957797", Drop: []string{"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4254", "CVE-2008-4255", "CVE-2008-4256"}},
			{KB: "958392", Drop: []string{"CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254"}},
			{KB: "958393", Drop: []string{"CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254"}},
		},
	},
	"MS08-073": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Vista", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2008-4258", "CVE-2008-4261"}},
		},
		IECumChain: map[string][]string{
			"956390": {"958215"},
		},
	},
	"MS08-078": {
		IECumChain: map[string][]string{
			"958215": {"960714"},
		},
	},
	"MS09-001": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-4834"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-4834"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2008-4834"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2008-4834"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2008-4834"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2008-4834"}},
		},
	},
	"MS09-003": {CVEAdjustments: []cveAdjustment{{KB: "959241", Drop: []string{"CVE-2009-0099"}}}},
	"MS09-005": {CVEAdjustments: []cveAdjustment{{KB: "957831", Drop: []string{"CVE-2009-0097"}}}},
	"MS09-006": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-0083"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0083"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-0083"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-0083"}},
		},
	},
	"MS09-008": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-0093", "CVE-2009-0094"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-0093", "CVE-2009-0094"}},
		},
	},
	"MS09-010": {
		CVEAdjustments: []cveAdjustment{
			{KB: "923561", Drop: []string{"CVE-2009-0088"}},
			{KB: "960476", Drop: []string{"CVE-2008-4841", "CVE-2009-0087", "CVE-2009-0235"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-0088"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2008-4841", "CVE-2009-0088"}},
		},
	},
	"MS09-012": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-0078", "CVE-2009-0079", "CVE-2009-0080"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows XP Professional x64 Edition", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-0080"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-0080"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-0079"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-0079"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-0079"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-0079"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-0079"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-0079"}},
		},
	},
	"MS09-013": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-0089"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-0089"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-0089"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-0089"}},
		},
		IECumChain: map[string][]string{
			"960714": {"963027"},
		},
	},
	"MS09-014": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-2540", "CVE-2009-0551", "CVE-2009-0553"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2008-2540"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 1", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Vista", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2008-2540", "CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition", Drop: []string{"CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-0552"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-0552"}},
		},
	},
	"MS09-016": {CVEAdjustments: []cveAdjustment{{KB: "961759", Drop: []string{"CVE-2009-0237"}}}},
	"MS09-017": {
		CVEAdjustments: []cveAdjustment{
			{KB: "967043", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "967044", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "969615", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "969618", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "969661", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "970059", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "971822", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
			{KB: "971824", Drop: []string{"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"}},
		},
	},
	"MS09-018": {CVEAdjustments: []cveAdjustment{{KB: "970437", Drop: []string{"CVE-2009-1138"}}}},
	"MS09-019": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2007-3091", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-1141", "CVE-2009-1532"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 2", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531"}},
		},
		IECumChain: map[string][]string{
			"963027": {"969897"},
		},
	},
	"MS09-020": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2009-1122", "CVE-2009-1535", "CVE-2009-1676"}}}},
	"MS09-021": {
		CVEAdjustments: []cveAdjustment{
			{KB: "969679", Drop: []string{"CVE-2009-0549", "CVE-2009-0558", "CVE-2009-0559"}},
			{KB: "969686", Drop: []string{"CVE-2009-0549", "CVE-2009-0558", "CVE-2009-0559"}},
			{KB: "969737", Drop: []string{"CVE-2009-0549", "CVE-2009-0557", "CVE-2009-0558", "CVE-2009-0559", "CVE-2009-0560", "CVE-2009-1134"}},
		},
	},
	"MS09-022": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-0228"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0228"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-0228"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-0228"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-0228"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-0228"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-0228"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-0228"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-0228"}},
		},
	},
	"MS09-025": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-1126"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-1126"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-1126"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-1126"}},
		},
	},
	"MS09-027": {CVEAdjustments: []cveAdjustment{{KB: "969614", Drop: []string{"CVE-2009-0565"}}}},
	"MS09-034": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-1917"}},
		},
		IECumChain: map[string][]string{
			"969897": {"972260"},
		},
	},
	"MS09-039": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1924"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1924"}},
		},
	},
	"MS09-043": {
		CVEAdjustments: []cveAdjustment{
			{KB: "947318", Drop: []string{"CVE-2009-1534"}},
			{KB: "947319", Drop: []string{"CVE-2009-1534"}},
			{KB: "947826", Drop: []string{"CVE-2009-1534"}},
			{KB: "968377", Drop: []string{"CVE-2009-1534"}},
			{KB: "969172", Drop: []string{"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"}},
			{KB: "971388", Drop: []string{"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"}},
			{Component: "Microsoft Office 2000 Web Components Service Pack 3", Drop: []string{"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"}},
		},
	},
	"MS09-044": {
		CVEAdjustments: []cveAdjustment{
			{KB: "974283", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-1929"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-1929"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-1929"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-1929"}},
		},
	},
	"MS09-047": {CVEAdjustments: []cveAdjustment{{KB: "972554", Drop: []string{"CVE-2009-2499"}}}},
	"MS09-048": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-1925"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1925"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1925"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1925"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-1925"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-1925"}},
		},
	},
	"MS09-054": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-2530", "CVE-2009-2531"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-1547"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-1547"}},
		},
		IECumChain: map[string][]string{
			"972260": {"974455"},
		},
	},
	"MS09-058": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-2517"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2517"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2517"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-2517"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-2516", "CVE-2009-2517"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-2516", "CVE-2009-2517"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2009-2516", "CVE-2009-2517"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-2517"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2516", "CVE-2009-2517"}},
		},
	},
	"MS09-061": {
		CVEAdjustments: []cveAdjustment{
			{KB: "953297", Drop: []string{"CVE-2009-0091", "CVE-2009-2497"}},
			{KB: "953298", Drop: []string{"CVE-2009-0091", "CVE-2009-2497"}},
			{KB: "970363", Drop: []string{"CVE-2009-0090", "CVE-2009-0091"}},
			{KB: "974470", Drop: []string{"CVE-2009-0090", "CVE-2009-0091"}},
		},
	},
	"MS09-062": {
		CVEAdjustments: []cveAdjustment{
			{KB: "957488", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "958869", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "970892", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "970895", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971022", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971023", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971104", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971105", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971108", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971111", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971117", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "971118", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "972221", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "972580", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "972581", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "973636", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "975337", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "975365", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{KB: "975962", Drop: []string{"CVE-2009-2518", "CVE-2009-2528"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-3126"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-3126"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-3126"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-3126"}},
		},
	},
	"MS09-065": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2514"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-2514"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2514"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-2514"}},
		},
	},
	"MS09-067": {
		CVEAdjustments: []cveAdjustment{
			{KB: "973484", Drop: []string{"CVE-2009-3130", "CVE-2009-3133"}},
			{KB: "973704", Drop: []string{"CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3130", "CVE-2009-3133"}},
			{KB: "973707", Drop: []string{"CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3130", "CVE-2009-3133"}},
			{KB: "976828", Drop: []string{"CVE-2009-3128"}},
			{KB: "976830", Drop: []string{"CVE-2009-3128"}},
			{KB: "976831", Drop: []string{"CVE-2009-3128"}},
		},
	},
	"MS09-071": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-2505"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-2505"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2505"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2505"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-2505"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-3677"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-3677"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2009-3677"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2009-2505"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-3677"}},
		},
	},
	"MS09-072": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3672", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-3671", "CVE-2009-3672", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-3671", "CVE-2009-3673", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3674"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-2493", "CVE-2009-3672"}},
		},
		IECumChain: map[string][]string{
			"974455": {"976325"},
		},
	},
	"MS10-002": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-4074", "CVE-2010-0244", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0248", "CVE-2010-0249"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0245", "CVE-2010-0246"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2009-4074", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-0247"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0247"}},
		},
		IECumChain: map[string][]string{
			"976325": {"978207"},
		},
	},
	"MS10-004": {CVEAdjustments: []cveAdjustment{{KB: "979674", Drop: []string{"CVE-2010-0029", "CVE-2010-0030", "CVE-2010-0032", "CVE-2010-0033", "CVE-2010-0034"}}}},
	"MS10-006": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0017"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0017"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0017"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0017"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2010-0017"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-0017"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0016"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0016"}},
		},
	},
	"MS10-012": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0021"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0021"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0021"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0021"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2010-0021"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-0021"}},
		},
	},
	"MS10-015": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0232"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0232"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0233"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0232"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0232"}},
		},
	},
	"MS10-017": {
		CVEAdjustments: []cveAdjustment{
			{KB: "978380", Drop: []string{"CVE-2010-0257", "CVE-2010-0262", "CVE-2010-0264"}},
			{KB: "978383", Drop: []string{"CVE-2010-0257", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0264"}},
			{KB: "979439", Drop: []string{"CVE-2010-0257", "CVE-2010-0258", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0264"}},
			{KB: "980837", Drop: []string{"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0263"}},
			{KB: "980839", Drop: []string{"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262"}},
			{KB: "980840", Drop: []string{"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262"}},
		},
	},
	"MS10-018": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 5.01 Service Pack 4 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0267", "CVE-2010-0490", "CVE-2010-0492", "CVE-2010-0494", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0492", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0492", "CVE-2010-0805", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0492", "CVE-2010-0805", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0492", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-0492", "CVE-2010-0807"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0492", "CVE-2010-0807"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0805"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0491", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"}},
		},
		IECumChain: map[string][]string{
			"978207": {"980182"},
		},
	},
	"MS10-020": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0476", "CVE-2010-0477"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0476", "CVE-2010-0477"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0476", "CVE-2010-0477"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0476", "CVE-2010-0477"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0477"}},
		},
	},
	"MS10-021": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0237", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0237", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0237", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Microsoft Windows XP Service Pack 2", Drop: []string{"CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0810"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0810"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0810"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Vista", Drop: []string{"CVE-2010-0237", "CVE-2010-0482"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Vista x64 Edition", Drop: []string{"CVE-2010-0237", "CVE-2010-0482"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0482"}},
		},
	},
	"MS10-024": {
		CVEAdjustments: []cveAdjustment{
			{KB: "976702", Drop: []string{"CVE-2010-0025"}},
			{KB: "976703", Drop: []string{"CVE-2010-0024"}},
			{KB: "981383", Drop: []string{"CVE-2010-0025"}},
			{KB: "981401", Drop: []string{"CVE-2010-0025"}},
			{KB: "981407", Drop: []string{"CVE-2010-0025"}},
		},
	},
	"MS10-032": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0484"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0484"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0484"}},
		},
	},
	"MS10-033": {
		CVEAdjustments: []cveAdjustment{
			{KB: "978695", Drop: []string{"CVE-2010-1880"}},
			{KB: "979332", Drop: []string{"CVE-2010-1880"}},
			{KB: "979482", Drop: []string{"CVE-2010-1880"}},
			{KB: "979902", Drop: []string{"CVE-2010-1880"}},
		},
	},
	"MS10-034": {CVEAdjustments: []cveAdjustment{{Component: "Microsoft Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0811"}}}},
	"MS10-035": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 Service Pack 1 for Windows 2000 Service Pack 4", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 2", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"}},
		},
		IECumChain: map[string][]string{
			"980182": {"982381"},
		},
	},
	"MS10-038": {
		CVEAdjustments: []cveAdjustment{
			{KB: "982331", Drop: []string{"CVE-2010-0822", "CVE-2010-0824", "CVE-2010-1245", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1249", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1254"}},
			{KB: "982333", Drop: []string{"CVE-2010-0822", "CVE-2010-0824", "CVE-2010-1245", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1249", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1253", "CVE-2010-1254"}},
			{KB: "2027452", Drop: []string{"CVE-2010-1254"}},
			{KB: "2028864", Drop: []string{"CVE-2010-0824", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1254"}},
			{KB: "2028866", Drop: []string{"CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1254"}},
			{KB: "2078051", Drop: []string{"CVE-2010-0824", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1251", "CVE-2010-1252"}},
		},
	},
	"MS10-039": {
		CVEAdjustments: []cveAdjustment{
			{KB: "979441", Drop: []string{"CVE-2010-0817", "CVE-2010-1264"}},
			{KB: "979445", Drop: []string{"CVE-2010-0817", "CVE-2010-1264"}},
			{KB: "980923", Drop: []string{"CVE-2010-0817", "CVE-2010-1264"}},
		},
	},
	"MS10-047": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-1889", "CVE-2010-1890"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-1888", "CVE-2010-1889"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-1888", "CVE-2010-1889"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-1888", "CVE-2010-1889"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-1888"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1888"}},
		},
	},
	"MS10-048": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-1894", "CVE-2010-1895", "CVE-2010-1896"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-1894", "CVE-2010-1895", "CVE-2010-1896"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-1894", "CVE-2010-1895", "CVE-2010-1896"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1894", "CVE-2010-1895"}},
		},
	},
	"MS10-049": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-2566"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2566"}},
		},
	},
	"MS10-053": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-2559"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2559"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2559"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-2557", "CVE-2010-2559"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2557"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-2557"}},
		},
		IECumChain: map[string][]string{
			"982381": {"2183461"},
		},
	},
	"MS10-054": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-2551", "CVE-2010-2552"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2551", "CVE-2010-2552"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2551", "CVE-2010-2552"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-2551", "CVE-2010-2552"}},
		},
	},
	"MS10-056": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2092914", Drop: []string{"CVE-2010-1901", "CVE-2010-1902", "CVE-2010-1903"}},
			{KB: "2277947", Drop: []string{"CVE-2010-1903"}},
			{KB: "2284162", Drop: []string{"CVE-2010-1903"}},
			{KB: "2284171", Drop: []string{"CVE-2010-1903"}},
			{KB: "2284179", Drop: []string{"CVE-2010-1903"}},
		},
	},
	"MS10-058": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-1893"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-1893"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-1893"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-1893"}},
		},
	},
	"MS10-060": {
		CVEAdjustments: []cveAdjustment{
			{KB: "982926", Drop: []string{"CVE-2010-0019"}},
			{KB: "983582", Drop: []string{"CVE-2010-0019"}},
			{KB: "983590", Drop: []string{"CVE-2010-0019"}},
			{KB: "2265906", Drop: []string{"CVE-2010-0019"}},
		},
	},
	"MS10-065": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2124261", Drop: []string{"CVE-2010-2730", "CVE-2010-2731"}},
			{KB: "2271195", Drop: []string{"CVE-2010-1899", "CVE-2010-2731"}},
			{KB: "2290570", Drop: []string{"CVE-2010-1899", "CVE-2010-2730"}},
		},
	},
	"MS10-071": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3329"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3329"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3329"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3329"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-0808", "CVE-2010-3326"}},
		},
		IECumChain: map[string][]string{
			"2183461": {"2360131"},
		},
	},
	"MS10-072": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2345322", Drop: []string{"CVE-2010-3243"}},
			{KB: "2346298", Drop: []string{"CVE-2010-3243"}},
			{KB: "2346411", Drop: []string{"CVE-2010-3243"}},
		},
	},
	"MS10-073": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-2549"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2549"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-2549"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-2549"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-2549"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-2549"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-2549"}},
		},
	},
	"MS10-079": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2345009", Drop: []string{"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220"}},
			{KB: "2345043", Drop: []string{"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"}},
			{KB: "2422343", Drop: []string{"CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219"}},
			{KB: "2422352", Drop: []string{"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"}},
			{KB: "2422398", Drop: []string{"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"}},
			{Component: "Microsoft Office Web Apps 2010", Drop: []string{"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"}},
		},
	},
	"MS10-080": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2344875", Drop: []string{"CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3241", "CVE-2010-3242"}},
			{KB: "2345088", Drop: []string{"CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3241", "CVE-2010-3242"}},
			{KB: "2422343", Drop: []string{"CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3239", "CVE-2010-3240"}},
			{KB: "2422352", Drop: []string{"CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240"}},
			{KB: "2422398", Drop: []string{"CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240"}},
		},
	},
	"MS10-087": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2289158", Drop: []string{"CVE-2010-2573", "CVE-2010-3336"}},
			{KB: "2289161", Drop: []string{"CVE-2010-2573", "CVE-2010-3336"}},
			{KB: "2289169", Drop: []string{"CVE-2010-3337"}},
			{KB: "2289187", Drop: []string{"CVE-2010-3336", "CVE-2010-3337"}},
			{KB: "2423930", Drop: []string{"CVE-2010-3337"}},
			{KB: "2454823", Drop: []string{"CVE-2010-2573", "CVE-2010-3334", "CVE-2010-3337"}},
			{KB: "2476511", Drop: []string{"CVE-2010-2573", "CVE-2010-3337"}},
			{KB: "2476512", Drop: []string{"CVE-2010-2573", "CVE-2010-3337"}},
		},
	},
	"MS10-088": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2413381", Drop: []string{"CVE-2010-2572"}},
			{Component: "Microsoft Office 2004 for Mac", Drop: []string{"CVE-2010-2572"}},
		},
	},
	"MS10-090": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-3345"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3340"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2010-3340"}},
		},
		IECumChain: map[string][]string{
			"2360131": {"2416400"},
		},
	},
	"MS10-098": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-3941"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-3941"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-3944"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3944"}},
		},
	},
	"MS10-105": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2288931", Drop: []string{"CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950"}},
			{KB: "2289078", Drop: []string{"CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950"}},
			{KB: "2289163", Drop: []string{"CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950", "CVE-2010-3951", "CVE-2010-3952"}},
			{KB: "2431831", Drop: []string{"CVE-2010-3945", "CVE-2010-3946", "CVE-2010-3949", "CVE-2010-3951", "CVE-2010-3952"}},
		},
	},
	"MS11-003": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0038"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-0038"}},
		},
		IECumChain: map[string][]string{
			"2416400": {"2482017"},
		},
	},
	"MS11-011": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-0045"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0045"}},
		},
	},
	"MS11-012": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-0087"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-0087"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-0087"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-0087"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-0087"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-0087"}},
		},
	},
	"MS11-013": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2425227", Drop: []string{"CVE-2011-0043"}},
			{KB: "2478971", Drop: []string{"CVE-2011-0091"}},
		},
	},
	// MS11-015: legacy bulletinArchiveKBNotApplicable entry for KB2479943
	// dropped both CVE-2011-0032 and CVE-2011-0042 as if KB-uniformly NA,
	// but the per-CVE matrix table actually has both CVEs APPLICABLE for
	// the Vista / Windows 7 / Server 2008 R2 rows that share KB2479943 —
	// only XP rows are NA for CVE-2011-0032, and only Server 2008 R2 is
	// NA for CVE-2011-0042 (per-product, not per-KB). Filtering at the
	// KB grain dropped every CVE from every row, leaving the bulletin
	// without any vulnerability entries and surfacing "MS11-015" as a
	// synthetic cveID in scannedCves on Server 2008 R2. The KB2479943
	// KB-Drop is removed here; KB2502898 is retained because it is
	// genuinely KB-uniformly NA per the same matrix (XP MCE 2005 SP3
	// row only). Ideal fix is per-product Component-Drop entries
	// (3 entries per the current generator output) — deferred since the
	// same staleness affects many other bulletins.
	// MS11-015: Format B (per-product Component-Drop) entries from the
	// current gen_static_map.py output. The markdown's per-CVE matrix
	// table marks CVE-2011-0032 NA on Microsoft Windows XP rows and
	// CVE-2011-0042 NA on Windows Server 2008 R2 rows. Component-Drop
	// keys use the xlsx affected_product form (with "Microsoft "
	// prefix where xlsx carries it) to match normalizeArchiveComponentKey
	// — MS11-015 is in the normalize switch returning `product`.
	"MS11-015": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2502898", Drop: []string{"CVE-2011-0032"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0032"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2011-0032"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-0042"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-0042"}},
		},
	},
	"MS11-018": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-0094", "CVE-2011-1245"}},
		},
		IECumChain: map[string][]string{
			"2482017": {"2497640"},
		},
	},
	"MS11-021": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2466156", Drop: []string{"CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0979", "CVE-2011-0980"}},
			{KB: "2466158", Drop: []string{"CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0980"}},
			{KB: "2505924", Drop: []string{"CVE-2011-0101"}},
			{KB: "2505927", Drop: []string{"CVE-2011-0101", "CVE-2011-0978"}},
			{KB: "2505935", Drop: []string{"CVE-2011-0101", "CVE-2011-0978"}},
			{KB: "2525412", Drop: []string{"CVE-2011-0097", "CVE-2011-0098", "CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0978", "CVE-2011-0980"}},
		},
	},
	"MS11-022": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2519984", Drop: []string{"CVE-2011-0976"}},
			{KB: "2525412", Drop: []string{"CVE-2011-0976"}},
		},
	},
	"MS11-023": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2505924", Drop: []string{"CVE-2011-0107"}},
			{KB: "2505927", Drop: []string{"CVE-2011-0107"}},
			{KB: "2505935", Drop: []string{"CVE-2011-0107"}},
		},
	},
	"MS11-027": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2010-3973", "CVE-2011-1243"}},
		},
	},
	"MS11-036": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2540162", Drop: []string{"CVE-2011-1270"}},
			{Component: "Microsoft Office 2004 for Mac", Drop: []string{"CVE-2011-1270"}},
			{Component: "Microsoft Office 2008 for Mac", Drop: []string{"CVE-2011-1270"}},
			{Component: "Open XML File Format Converter for Mac", Drop: []string{"CVE-2011-1270"}},
		},
	},
	"MS11-042": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-1868"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1868"}},
		},
	},
	"MS11-045": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2541012", Drop: []string{"CVE-2011-1275", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"}},
			{KB: "2541015", Drop: []string{"CVE-2011-1275", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"}},
			{KB: "2555784", Drop: []string{"CVE-2011-1272", "CVE-2011-1274", "CVE-2011-1276", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"}},
			{KB: "2555785", Drop: []string{"CVE-2011-1278"}},
			{KB: "2555786", Drop: []string{"CVE-2011-1277"}},
			{KB: "2555787", Drop: []string{"CVE-2011-1278"}},
		},
	},
	"MS11-050": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2011-1246", "CVE-2011-1250", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258", "CVE-2011-1260", "CVE-2011-1261", "CVE-2011-1262", "CVE-2011-1346"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1260", "CVE-2011-1262"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1260", "CVE-2011-1262"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1260", "CVE-2011-1262"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1260", "CVE-2011-1262"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 1", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1260"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258"}},
		},
		IECumChain: map[string][]string{
			"2497640": {"2530548"},
		},
	},
	"MS11-054": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1877", "CVE-2011-1886", "CVE-2011-1887", "CVE-2011-1888"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1877", "CVE-2011-1886", "CVE-2011-1887", "CVE-2011-1888"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1877", "CVE-2011-1886", "CVE-2011-1887", "CVE-2011-1888"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2011-1877", "CVE-2011-1887", "CVE-2011-1888"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-1886"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1886"}},
		},
	},
	// (MS08-032 / CVE-2007-0675 omitted: the archive markdown at
	// ms08-032.md is mis-mapped — its content is actually MS16-011's — so
	// the absence-in-markdown signal cannot distinguish typo from real
	// attribution. CVE-2007-0675 is a real ActiveX vulnerability addressed
	// by the MS08-032 Cumulative ActiveX Kill Bit update.)
	// MS11-056: off-by-one of CVE-2011-1284 — remap (1284 not in xlsx).
	"MS11-056": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1283", "CVE-2011-1870"}},
			{Component: "Windows Server 2008 for 32-bit Systems", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Server 2008 for x64-based Systems", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Vista Service Pack 1", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Vista x64 Edition Service Pack 1", Drop: []string{"CVE-2011-1870"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1870"}},
			{Remap: map[string]string{"CVE-2011-1285": "CVE-2011-1284"}},
		},
	},
	// MS11-057 includes CVE-2011-1347 because the bulletin's update FAQ
	// states "this update addresses a Protected Mode bypass issue,
	// publicly disclosed". The CVE is not in the main vulnerability
	// table but the update explicitly addresses it.
	"MS11-057": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2011-1257", "CVE-2011-1347", "CVE-2011-1960", "CVE-2011-1961", "CVE-2011-1962", "CVE-2011-1963", "CVE-2011-1964", "CVE-2011-2383"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1963"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1963"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1963"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1963"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1257"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1257"}},
		},
		IECumChain: map[string][]string{
			"2530548": {"2559049"},
		},
	},
	"MS11-058": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1966"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1966"}},
		},
	},
	"MS11-060": {CVEAdjustments: []cveAdjustment{{KB: "2560978", Drop: []string{"CVE-2011-1979"}}}},
	"MS11-064": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1965"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1965"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1965"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1965"}},
		},
	},
	"MS11-072": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553074", Drop: []string{"CVE-2011-1986"}},
			{KB: "2553075", Drop: []string{"CVE-2011-1986"}},
			{KB: "2553089", Drop: []string{"CVE-2011-1986"}},
			{KB: "2553091", Drop: []string{"CVE-2011-1986", "CVE-2011-1988", "CVE-2011-1990"}},
			{KB: "2553093", Drop: []string{"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-1988"}},
			{KB: "2598781", Drop: []string{"CVE-2011-1986", "CVE-2011-1990"}},
			{KB: "2598782", Drop: []string{"CVE-2011-1986", "CVE-2011-1990"}},
			{KB: "2598783", Drop: []string{"CVE-2011-1986", "CVE-2011-1988", "CVE-2011-1990"}},
			{KB: "2598785", Drop: []string{"CVE-2011-1986", "CVE-2011-1990"}},
		},
	},
	"MS11-073": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2584052", Drop: []string{"CVE-2011-1982"}},
			{KB: "2584066", Drop: []string{"CVE-2011-1980"}},
		},
	},
	"MS11-074": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2493987", Drop: []string{"CVE-2011-0653", "CVE-2011-1890"}},
			{KB: "2494007", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1892"}},
			{KB: "2508965", Drop: []string{"CVE-2011-0653", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2552997", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2552998", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2552999", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2553005", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2566445", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{KB: "2566449", Drop: []string{"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"}},
			{Component: "Microsoft SharePoint Foundation 2010 Service Pack 1", Drop: []string{"CVE-2011-0653", "CVE-2011-1890", "CVE-2011-1892", "CVE-2011-1893"}},
		},
	},
	"MS11-077": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-2002"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-2002"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-2002"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2011-2002"}},
		},
	},
	"MS11-081": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1997", "CVE-2011-1998"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1999"}},
		},
		IECumChain: map[string][]string{
			"2559049": {"2586448"},
		},
	},
	"MS11-090": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2011-3397"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-3397"}},
		},
	},
	"MS11-091": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412"}}}},
	"MS11-094": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2596843", Drop: []string{"CVE-2011-3396"}},
			{KB: "2596912", Drop: []string{"CVE-2011-3396"}},
			{KB: "2644354", Drop: []string{"CVE-2011-3396"}},
		},
	},
	"MS11-096": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-3403"}}}},
	// MS11-099: off-by-one of CVE-2011-3404 — remap (3404 not in xlsx).
	// CVE-2011-3403 itself appears in MS11-096's markdown.
	"MS11-099": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2011-1992", "CVE-2011-2019", "CVE-2011-3389", "CVE-2011-3404"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2011-2019"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2011-1992"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2011-1992", "CVE-2011-2019"}},
			{Remap: map[string]string{"CVE-2011-3403": "CVE-2011-3404"}},
		},
		IECumChain: map[string][]string{
			"2586448": {"2618444"},
		},
	},
	"MS11-100": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2011-3414", "CVE-2011-3415", "CVE-2011-3416", "CVE-2011-3417", "CVE-2012-0160", "CVE-2012-0161"}},
			{KB: "2656353", Drop: []string{"CVE-2011-3415"}},
			{KB: "2656358", Drop: []string{"CVE-2011-3415"}},
		},
	},
	"MS12-004": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-0003"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-0003"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-0003"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0003"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-0003"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0003"}},
		},
	},
	"MS12-009": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0148"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0149"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0149"}},
		},
	},
	"MS12-010": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0011", "CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0011", "CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0011", "CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0011", "CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0012", "CVE-2012-0155"}},
		},
		IECumChain: map[string][]string{
			"2618444": {"2647516"},
		},
	},
	"MS12-016": {CVEAdjustments: []cveAdjustment{{KB: "2668562", Drop: []string{"CVE-2012-0015"}}}},
	"MS12-020": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2012-0152"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0152"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0152"}},
		},
	},
	"MS12-023": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0169"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-0169", "CVE-2012-0170"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0170", "CVE-2012-0172"}},
		},
		IECumChain: map[string][]string{
			"2647516": {"2675157"},
		},
	},
	"MS12-030": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553371", Drop: []string{"CVE-2012-0143"}},
			{KB: "2596842", Drop: []string{"CVE-2012-0143"}},
			{KB: "2597162", Drop: []string{"CVE-2012-0143"}},
			{KB: "2597969", Drop: []string{"CVE-2012-0143"}},
			{KB: "2665346", Drop: []string{"CVE-2012-0141", "CVE-2012-0185"}},
			{KB: "2665351", Drop: []string{"CVE-2012-0142", "CVE-2012-0143", "CVE-2012-0185"}},
		},
	},
	"MS12-032": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-0179"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-0179"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2012-0179"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-0179"}},
		},
	},
	"MS12-034": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2589337", Drop: []string{"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"}},
			{KB: "2598253", Drop: []string{"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"}},
			{KB: "2636927", Drop: []string{"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0165", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"}},
			{KB: "2690729", Drop: []string{"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0165", "CVE-2012-0167", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"}},
		},
	},
	"MS12-037": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1873", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1873", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1873", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-1858", "CVE-2012-1873", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-1858", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1523", "CVE-2012-1875"}},
		},
		IECumChain: map[string][]string{
			"2675157": {"2699988"},
		},
	},
	"MS12-039": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858"}},
			{KB: "2702444", Drop: []string{"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1858"}},
			{KB: "2708980", Drop: []string{"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849"}},
		},
	},
	"MS12-041": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1868"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1868"}},
		},
	},
	"MS12-042": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2707511", Drop: []string{"CVE-2012-0217"}},
			{KB: "2709715", Drop: []string{"CVE-2012-1515"}},
		},
	},
	"MS12-044": {
		IECumChain: map[string][]string{
			"2699988": {"2719177"},
		},
	},
	"MS12-050": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553431", Drop: []string{"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"}},
			{KB: "2589325", Drop: []string{"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"}},
			{KB: "2596666", Drop: []string{"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"}},
			{KB: "2598239", Drop: []string{"CVE-2012-1862", "CVE-2012-1863"}},
			{KB: "2760604", Drop: []string{"CVE-2012-1858", "CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862"}},
			{Component: "Microsoft SharePoint Foundation 2010", Drop: []string{"CVE-2012-1860", "CVE-2012-1862"}},
			{Component: "Microsoft SharePoint Foundation 2010 Service Pack 1", Drop: []string{"CVE-2012-1860", "CVE-2012-1862"}},
			{Component: "Microsoft SharePoint Server 2010", Drop: []string{"CVE-2012-1862", "CVE-2012-1863"}},
			{Component: "Microsoft SharePoint Server 2010 Service Pack 1", Drop: []string{"CVE-2012-1862", "CVE-2012-1863"}},
		},
	},
	"MS12-052": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1526"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1526", "CVE-2012-2523"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1526"}},
		},
		IECumChain: map[string][]string{
			"2699988": {"2722913"},
			"2719177": {"2722913"},
		},
	},
	"MS12-054": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2705219", Drop: []string{"CVE-2012-1851"}},
			{KB: "2712808", Drop: []string{"CVE-2012-1850", "CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1853"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2003 with SP2 for Itanium-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1852", "CVE-2012-1853"}},
			{Component: "Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1853"}},
		},
	},
	"MS12-063": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-2546", "CVE-2012-2548"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-2557"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2557"}},
		},
		IECumChain: map[string][]string{
			"2722913": {"2744842"},
		},
	},
	"MS12-064": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2687314", Drop: []string{"CVE-2012-0182"}},
			{KB: "2687401", Drop: []string{"CVE-2012-0182"}},
			{KB: "2687485", Drop: []string{"CVE-2012-0182"}},
		},
	},
	"MS12-071": {
		IECumChain: map[string][]string{
			"2744842": {"2761451"},
		},
	},
	"MS12-073": {CVEAdjustments: []cveAdjustment{{KB: "2716513", Drop: []string{"CVE-2012-2531"}}}},
	"MS12-074": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2698023", Drop: []string{"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"}},
			{KB: "2698032", Drop: []string{"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"}},
			{KB: "2698035", Drop: []string{"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"}},
			{KB: "2729449", Drop: []string{"CVE-2012-1896", "CVE-2012-4777"}},
			{KB: "2729450", Drop: []string{"CVE-2012-4777"}},
			{KB: "2729451", Drop: []string{"CVE-2012-4777"}},
			{KB: "2729452", Drop: []string{"CVE-2012-4777"}},
			{KB: "2729453", Drop: []string{"CVE-2012-4777"}},
			{KB: "2729460", Drop: []string{"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4777"}},
			{KB: "2729462", Drop: []string{"CVE-2012-1896", "CVE-2012-4777"}},
			{KB: "2737019", Drop: []string{"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"}},
			{KB: "2737083", Drop: []string{"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"}},
			{KB: "2737084", Drop: []string{"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"}},
			{KB: "2756872", Drop: []string{"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4777"}},
			{Component: "Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems", Drop: []string{"CVE-2012-1895"}},
			{Component: "Microsoft .NET Framework 3.5 on Windows 8 for x64-based Systems", Drop: []string{"CVE-2012-1895"}},
			{Component: "Microsoft .NET Framework 3.5 on Windows Server 2012", Drop: []string{"CVE-2012-1895"}},
		},
	},
	"MS12-075": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2553"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2012-2530", "CVE-2012-2553"}},
			{Component: "Windows RT", Drop: []string{"CVE-2012-2530", "CVE-2012-2553"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems (Server Core installation)", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2012-2553"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2012-2530", "CVE-2012-2553"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2012-2530", "CVE-2012-2553"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-2553"}},
		},
	},
	"MS12-076": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2687311", Drop: []string{"CVE-2012-1887"}},
			{KB: "2687313", Drop: []string{"CVE-2012-1885", "CVE-2012-1887"}},
			{KB: "2764047", Drop: []string{"CVE-2012-1886"}},
			{KB: "2764048", Drop: []string{"CVE-2012-1886", "CVE-2012-2543"}},
		},
	},
	"MS12-077": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2012-4782", "CVE-2012-4787"}},
		},
		IECumChain: map[string][]string{
			"2744842": {"2761465"},
			"2761451": {"2761465"},
		},
	},
	"MS12-080": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2012-3214", "CVE-2012-3217", "CVE-2012-4791"}}}},
	"MS13-002": {CVEAdjustments: []cveAdjustment{{KB: "2758694", Drop: []string{"CVE-2013-0006"}}}},
	"MS13-004": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2742597", Drop: []string{"CVE-2013-0003"}},
			{KB: "2742598", Drop: []string{"CVE-2013-0001"}},
			{KB: "2742599", Drop: []string{"CVE-2013-0001"}},
			{KB: "2742604", Drop: []string{"CVE-2013-0003"}},
			{KB: "2742607", Drop: []string{"CVE-2013-0003"}},
			{KB: "2742613", Drop: []string{"CVE-2013-0001"}},
			{KB: "2742614", Drop: []string{"CVE-2013-0001"}},
			{KB: "2742616", Drop: []string{"CVE-2013-0001"}},
			{KB: "2756920", Drop: []string{"CVE-2013-0001"}},
			{KB: "2756921", Drop: []string{"CVE-2013-0001"}},
			{KB: "2756923", Drop: []string{"CVE-2013-0001"}},
		},
	},
	"MS13-008": {
		IECumChain: map[string][]string{
			"2761465": {"2799329"},
		},
	},
	"MS13-009": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0019", "CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0019", "CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0019", "CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0019", "CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0026"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0025"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-0015", "CVE-2013-0018", "CVE-2013-0020", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026", "CVE-2013-0028", "CVE-2013-0029"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-0015", "CVE-2013-0018", "CVE-2013-0020", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026", "CVE-2013-0028", "CVE-2013-0029"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-0015", "CVE-2013-0018", "CVE-2013-0020", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026", "CVE-2013-0028", "CVE-2013-0029"}},
		},
		IECumChain: map[string][]string{
			"2761465": {"2792100"},
			"2799329": {"2792100"},
		},
	},
	"MS13-016": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-1250", "CVE-2013-1251", "CVE-2013-1252", "CVE-2013-1253", "CVE-2013-1254", "CVE-2013-1255", "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259", "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263", "CVE-2013-1264", "CVE-2013-1265", "CVE-2013-1266", "CVE-2013-1267", "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271", "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275", "CVE-2013-1276", "CVE-2013-1277"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-1250", "CVE-2013-1251", "CVE-2013-1252", "CVE-2013-1253", "CVE-2013-1254", "CVE-2013-1255", "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259", "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263", "CVE-2013-1264", "CVE-2013-1265", "CVE-2013-1266", "CVE-2013-1267", "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271", "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275", "CVE-2013-1276", "CVE-2013-1277"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-1250", "CVE-2013-1251", "CVE-2013-1252", "CVE-2013-1253", "CVE-2013-1254", "CVE-2013-1255", "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259", "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263", "CVE-2013-1264", "CVE-2013-1265", "CVE-2013-1266", "CVE-2013-1267", "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271", "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275", "CVE-2013-1276", "CVE-2013-1277"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2013-1250", "CVE-2013-1251", "CVE-2013-1252", "CVE-2013-1253", "CVE-2013-1254", "CVE-2013-1255", "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259", "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263", "CVE-2013-1264", "CVE-2013-1265", "CVE-2013-1266", "CVE-2013-1267", "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271", "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275", "CVE-2013-1276", "CVE-2013-1277"}},
		},
	},
	"MS13-021": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-0091", "CVE-2013-1288"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2797052": {Add: []string{"2809289"}},
		},
		IECumChain: map[string][]string{
			"2792100": {"2809289"},
		},
	},
	"MS13-024": {CVEAdjustments: []cveAdjustment{{KB: "2687418", Drop: []string{"CVE-2013-0083"}}}},
	// MS13-028: no candidate in markdown — drop both.
	"MS13-028": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2013-1303", "CVE-2013-1304", "CVE-2013-1338"}},
			{Remap: map[string]string{"CVE-2013-2013": "", "CVE-2013-2014": ""}},
		},
		IECumChain: map[string][]string{
			"2809289": {"2817183"},
		},
	},
	"MS13-031": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows 7 for 32-bit Systems", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows 7 for x64-based Systems", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems (Server Core installation)", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2013-1284"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1284"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2620712": {Add: []string{"2813170"}},
		},
	},
	"MS13-032": {
		Supersedes: map[string]supersedesAdjust{
			"2621146": {Add: []string{"2772930"}},
			"2626416": {Override: []string{"2772930"}},
		},
	},
	"MS13-033": {
		Supersedes: map[string]supersedesAdjust{
			"2646524": {Add: []string{"2820917"}},
		},
	},
	"MS13-036": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2808735", Drop: []string{"CVE-2013-1293"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-1292"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1291", "CVE-2013-1292"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1291", "CVE-2013-1292"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2013-1292"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-1291"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-1291"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2013-1291"}},
		},
	},
	// MS13-037: off-by-one of CVE-2013-1312 — drop, 1312 already in xlsx.
	// CVE-2013-1313 appears in MS13-020's markdown.
	"MS13-037": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-0811", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-1306", "CVE-2013-1310", "CVE-2013-1312", "CVE-2013-3140"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-1297", "CVE-2013-1310", "CVE-2013-1311"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-3140"}},
			{Remap: map[string]string{"CVE-2013-1313": ""}},
		},
		IECumChain: map[string][]string{
			"2817183": {"2829530"},
		},
	},
	"MS13-038": {
		IECumChain: map[string][]string{
			"2829530": {"2847204"},
		},
	},
	"MS13-040": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2804576", Drop: []string{"CVE-2013-1337"}},
			{KB: "2804577", Drop: []string{"CVE-2013-1337"}},
			{KB: "2804579", Drop: []string{"CVE-2013-1337"}},
			{KB: "2804580", Drop: []string{"CVE-2013-1337"}},
			{KB: "2804584", Drop: []string{"CVE-2013-1337"}},
		},
	},
	"MS13-046": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2829361", Drop: []string{"CVE-2013-1332"}},
			{KB: "2830290", Drop: []string{"CVE-2013-1333", "CVE-2013-1334"}},
			{Component: "Windows 8 for 32-bit Systems (ntoskrnl.exe)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows 8 for 64-bit Systems (ntoskrnl.exe)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows RT (ntoskrnl.exe)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2003 Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2003 with SP2 for Itanium-based Systems (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2003 x64 Edition Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation) (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation) (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation) (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2012 (Server Core installation) (ntoskrnl.exe)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Server 2012 (ntoskrnl.exe)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Vista Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows Vista x64 Edition Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows XP Professional x64 Edition Service Pack 2 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
			{Component: "Windows XP Service Pack 3 (Win32k.sys)", Drop: []string{"CVE-2013-1333"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2813170": {Add: []string{"2829361"}},
		},
	},
	"MS13-047": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3114", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3118", "CVE-2013-3120", "CVE-2013-3125"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3110", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3122", "CVE-2013-3124", "CVE-2013-3141"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2847204": {Add: []string{"2838727"}},
		},
		IECumChain: map[string][]string{
			"2829530": {"2838727"},
			"2847204": {"2838727"},
		},
	},
	"MS13-048": {
		Supersedes: map[string]supersedesAdjust{
			"2829361": {Add: []string{"2839229"}},
		},
	},
	"MS13-052": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2832407", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2832411", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2832412", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2832414", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2832418", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833940", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833941", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833946", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833947", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833949", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833951", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833957", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833958", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2833959", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2835393", Drop: []string{"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2835622", Drop: []string{"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"}},
			{KB: "2840628", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2840629", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2840631", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2840632", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2840633", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2840642", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2844285", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2844286", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2844287", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2844289", Drop: []string{"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"}},
			{KB: "2847559", Drop: []string{"CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2698035": {Add: []string{"2833951"}},
		},
	},
	"MS13-053": {
		Supersedes: map[string]supersedesAdjust{
			"2808735": {Add: []string{"2850851"}},
		},
	},
	"MS13-054": {
		Supersedes: map[string]supersedesAdjust{
			"2598253": {Override: []string{"2817480"}},
			"2827750": {Override: []string{"2843162", "2843163"}},
			"2827751": {Add: []string{"2843162"}},
			"2827752": {Add: []string{"2843163"}},
		},
	},
	"MS13-055": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3143", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3150", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3846"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3146", "CVE-2013-3149", "CVE-2013-3152", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3145", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3164"}},
		},
		IECumChain: map[string][]string{
			"2838727": {"2846071"},
		},
	},
	// MS13-059: off-by-3 of CVE-2013-3184 — drop, 3184 already in xlsx.
	// CVE-2013-3181 appears in MS13-060's markdown.
	"MS13-059": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3192", "CVE-2013-3193", "CVE-2013-3194", "CVE-2013-3199"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3194"}},
			{Remap: map[string]string{"CVE-2013-3181": ""}},
		},
		IECumChain: map[string][]string{
			"2846071": {"2862772"},
		},
	},
	"MS13-060": {
		Supersedes: map[string]supersedesAdjust{
			"981322": {Add: []string{"2850869"}},
		},
	},
	"MS13-061": {
		Supersedes: map[string]supersedesAdjust{
			"2746164": {Add: []string{"2874216"}},
		},
	},
	"MS13-062": {
		Supersedes: map[string]supersedesAdjust{
			"970238":  {Add: []string{"2849470"}},
			"2360937": {Add: []string{"2849470"}},
		},
	},
	"MS13-063": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2013-2556", "CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-2556"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2013-2556"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-2556"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2644615": {Add: []string{"2859537"}},
			"2790113": {Add: []string{"2859537"}},
		},
	},
	"MS13-067": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553408", Drop: []string{"CVE-2013-1315", "CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2760589", Drop: []string{"CVE-2013-1330", "CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2760595", Drop: []string{"CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2760755", Drop: []string{"CVE-2013-3180"}},
			{Component: "Microsoft Office Web Apps Server 2013", Drop: []string{"CVE-2013-1315", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"}},
			{Component: "Microsoft SharePoint Portal Server 2003 Service Pack 3", Drop: []string{"CVE-2013-3179"}},
		},
	},
	// MS13-069: legacy bulletinArchiveKBNotApplicable entry for KB2870699
	// dropped all 10 CVEs as if KB-uniformly NA, but the current
	// gen_static_map.py output has zero KB-keyed NA entries for this
	// bulletin (all narrowing is per-(product, component) in the
	// markdown's per-CVE IE matrix table). The legacy entry filtered
	// every CVE from every xlsx row of KB2870699, leaving the bulletin
	// without vulnerability entries and surfacing "MS13-069" as a
	// synthetic cveID in scannedCves on Server 2008. The KB2870699
	// KB-Drop is removed here. IECumChain is retained as-is.
	// Ideal fix is 41 per-(IE, OS) Component-Drop entries (per the
	// current generator output) plus a normalizeArchiveComponentKey
	// special-case that constructs combined "IE X for/in Windows Y"
	// keys — deferred since the same staleness affects many other
	// IE Cumulative bulletins.
	"MS13-069": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3204", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3204", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3204", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3204", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3209"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3202", "CVE-2013-3205"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3205", "CVE-2013-3845"}},
		},
		IECumChain: map[string][]string{
			"2862772": {"2870699"},
		},
	},
	"MS13-072": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2597973", Drop: []string{"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2760411", Drop: []string{"CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2760823", Drop: []string{"CVE-2013-3160", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3856"}},
			{KB: "2817474", Drop: []string{"CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"}},
			{KB: "2817683", Drop: []string{"CVE-2013-3853", "CVE-2013-3854"}},
		},
	},
	"MS13-073": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2760588", Drop: []string{"CVE-2013-3158"}},
			{KB: "2760590", Drop: []string{"CVE-2013-3158"}},
			{KB: "2877813", Drop: []string{"CVE-2013-3158", "CVE-2013-3159"}},
		},
	},
	"MS13-076": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2013-1341", "CVE-2013-1342", "CVE-2013-1343", "CVE-2013-1344", "CVE-2013-3864", "CVE-2013-3865", "CVE-2013-3866"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-1341"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-1341"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2013-1341"}},
		},
	},
	"MS13-077": {
		Supersedes: map[string]supersedesAdjust{
			"2859537": {Add: []string{"2872339", "3033395"}},
		},
	},
	"MS13-080": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2884101", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3882", "CVE-2013-3885"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3874", "CVE-2013-3875"}},
		},
		IECumChain: map[string][]string{
			"2870699": {"2879017"},
		},
	},
	"MS13-081": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2847311", Drop: []string{"CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2855844", Drop: []string{"CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2862330", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2862335", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2863725", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2864202", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2868038", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{KB: "2876284", Drop: []string{"CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3894"}},
			{KB: "2883150", Drop: []string{"CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3888"}},
			{KB: "2884256", Drop: []string{"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows 8 for 64-bit Systems", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2003 with SP2 for Itanium-based Systems", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2013-3880"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2013-3881"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
			{Component: "Windows XP Service Pack 3", Drop: []string{"CVE-2013-3880", "CVE-2013-3881"}},
		},
	},
	"MS13-082": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2858302", Drop: []string{"CVE-2013-3128"}},
			{KB: "2861188", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861189", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861190", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861191", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861193", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861194", Drop: []string{"CVE-2013-3860", "CVE-2013-3861"}},
			{KB: "2861208", Drop: []string{"CVE-2013-3128"}},
			{KB: "2861697", Drop: []string{"CVE-2013-3128"}},
			{KB: "2861698", Drop: []string{"CVE-2013-3128"}},
			{KB: "2861702", Drop: []string{"CVE-2013-3128"}},
			{KB: "2861704", Drop: []string{"CVE-2013-3128"}},
			{KB: "2863239", Drop: []string{"CVE-2013-3128"}},
			{KB: "2863240", Drop: []string{"CVE-2013-3128"}},
			{KB: "2863243", Drop: []string{"CVE-2013-3128"}},
			{KB: "2863253", Drop: []string{"CVE-2013-3128"}},
		},
	},
	"MS13-085": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2760585", Drop: []string{"CVE-2013-3890"}},
			{KB: "2760591", Drop: []string{"CVE-2013-3890"}},
			{KB: "2817623", Drop: []string{"CVE-2013-3890"}},
			{KB: "2826023", Drop: []string{"CVE-2013-3890"}},
			{KB: "2826033", Drop: []string{"CVE-2013-3890"}},
			{KB: "2826035", Drop: []string{"CVE-2013-3890"}},
			{KB: "2827238", Drop: []string{"CVE-2013-3890"}},
			{KB: "2889496", Drop: []string{"CVE-2013-3890"}},
		},
	},
	"MS13-086": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2826020", Drop: []string{"CVE-2013-3892"}},
			{KB: "2827329", Drop: []string{"CVE-2013-3891"}},
			{KB: "2827330", Drop: []string{"CVE-2013-3891"}},
		},
	},
	"MS13-088": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-3911", "CVE-2013-3914"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3909"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows 8 for x64-based Systems", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-3909", "CVE-2013-3910"}},
			{Component: "Internet Explorer 11 for Windows RT 8.1", Drop: []string{"CVE-2013-3871", "CVE-2013-3908", "CVE-2013-3909", "CVE-2013-3910", "CVE-2013-3911"}},
			{Component: "Internet Explorer 11 for Windows Server 2012 R2", Drop: []string{"CVE-2013-3871", "CVE-2013-3908", "CVE-2013-3909", "CVE-2013-3910", "CVE-2013-3911"}},
		},
		IECumChain: map[string][]string{
			"2879017": {"2888505"},
			"2884101": {"2888505"},
		},
	},
	"MS13-091": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Office 2010 Service Pack 1 (32-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2010 Service Pack 1 (64-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2010 Service Pack 2 (32-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2010 Service Pack 2 (64-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2013 (32-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2013 (64-bit editions)", Drop: []string{"CVE-2013-0082", "CVE-2013-1325"}},
			{Component: "Microsoft Office 2013 RT", Drop: []string{"CVE-2013-0082", "CVE-2013-1325"}},
		},
	},
	"MS13-097": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5046", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 6 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5046", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 6 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5046", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 6 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-5045", "CVE-2013-5046", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 7 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-5045", "CVE-2013-5051"}},
			{Component: "Internet Explorer 8 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 8 for Windows XP Service Pack 3", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows Vista Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 9 for Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-5045", "CVE-2013-5051", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows 8 for x64-based Systems", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows RT", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 10 for Windows Server 2012", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 11 for Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 11 for Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 11 for Windows RT 8.1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 11 for Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
			{Component: "Internet Explorer 11 for Windows Server 2012 R2", Drop: []string{"CVE-2013-5049", "CVE-2013-5052"}},
		},
		IECumChain: map[string][]string{
			"2888505": {"2898785"},
		},
	},
	"MS13-101": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2887069", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903", "CVE-2013-5058"}},
			{KB: "2893984", Drop: []string{"CVE-2013-3907"}},
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Microsoft Windows XP Professional x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Microsoft Windows XP Service Pack 3", Drop: []string{"CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2013-3899", "CVE-2013-3903"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3899", "CVE-2013-3903"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2013-3899", "CVE-2013-3902"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2013-3899", "CVE-2013-3902"}},
			{Component: "Windows RT", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-5058"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-5058"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2013-3899", "CVE-2013-3903"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2013-3899", "CVE-2013-3903"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2013-3899", "CVE-2013-3902"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2013-3899", "CVE-2013-3902"}},
			{Component: "Windows Server 2012 R2 (server core installation)", Drop: []string{"CVE-2013-3899", "CVE-2013-3902"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903"}},
		},
	},
	"MS13-105": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2903911", Drop: []string{"CVE-2013-5072"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2866475": {Add: []string{"2880833"}},
		},
	},
	"MS14-001": {CVEAdjustments: []cveAdjustment{{KB: "2863867", Drop: []string{"CVE-2014-0259"}}}},
	"MS14-009": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2898855", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898856", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898857", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898858", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898860", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898864", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898865", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898866", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898868", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898869", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898870", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2898871", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2901110", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901111", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901112", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901113", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901115", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901118", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901119", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901120", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901125", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901126", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901127", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2901128", Drop: []string{"CVE-2014-0257", "CVE-2014-0295"}},
			{KB: "2904878", Drop: []string{"CVE-2014-0253", "CVE-2014-0295"}},
			{KB: "2911501", Drop: []string{"CVE-2014-0253", "CVE-2014-0257"}},
			{KB: "2911502", Drop: []string{"CVE-2014-0253", "CVE-2014-0257"}},
		},
	},
	"MS14-010": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-0267", "CVE-2014-0268", "CVE-2014-0270", "CVE-2014-0272", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0281", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0287", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-0267", "CVE-2014-0268", "CVE-2014-0270", "CVE-2014-0272", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0281", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0287", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-0267", "CVE-2014-0270", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-0267", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0289", "CVE-2014-0290"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-0267", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0283", "CVE-2014-0289", "CVE-2014-0290"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-0269", "CVE-2014-0272", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0283", "CVE-2014-0284"}},
		},
		IECumChain: map[string][]string{
			"2898785": {"2909921"},
		},
	},
	"MS14-012": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-0297", "CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0308", "CVE-2014-0309", "CVE-2014-0312", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-0324", "CVE-2014-4112"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-0297", "CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0308", "CVE-2014-0309", "CVE-2014-0312", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-0324", "CVE-2014-4112"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0307", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-4112"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0304", "CVE-2014-0313", "CVE-2014-0321", "CVE-2014-4112"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-4112"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0309", "CVE-2014-0314", "CVE-2014-0322"}},
		},
		IECumChain: map[string][]string{
			"2909921": {"2925418"},
		},
	},
	"MS14-017": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2863907", Drop: []string{"CVE-2014-1757", "CVE-2014-1758"}},
			{KB: "2878220", Drop: []string{"CVE-2014-1757", "CVE-2014-1758"}},
			{KB: "2878236", Drop: []string{"CVE-2014-1758"}},
			{KB: "2878304", Drop: []string{"CVE-2014-1757", "CVE-2014-1758"}},
			{KB: "2939132", Drop: []string{"CVE-2014-1757", "CVE-2014-1758"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2837615": {Add: []string{"2878236"}},
			"2863867": {Add: []string{"2878304"}},
			"2889496": {Add: []string{"2939132"}},
		},
	},
	"MS14-018": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1755", "CVE-2014-1760"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1755", "CVE-2014-1760"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1755", "CVE-2014-1760"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-1752", "CVE-2014-1760"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1753", "CVE-2014-1755", "CVE-2014-1760"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1753", "CVE-2014-1755"}},
		},
		IECumChain: map[string][]string{
			"2925418": {"2936068"},
		},
	},
	"MS14-021": {
		IECumChain: map[string][]string{
			"2925418": {"2964358"},
			"2936068": {"2964358"},
			"2964358": {"2964444"},
		},
	},
	"MS14-022": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2596861", Drop: []string{"CVE-2014-1754", "CVE-2014-1813"}},
			{KB: "2810069", Drop: []string{"CVE-2014-1754", "CVE-2014-1813"}},
			{KB: "2837598", Drop: []string{"CVE-2014-1754", "CVE-2014-1813"}},
			{KB: "2863829", Drop: []string{"CVE-2014-1813"}},
			{KB: "2863836", Drop: []string{"CVE-2014-1754", "CVE-2014-1813"}},
			{KB: "2863854", Drop: []string{"CVE-2014-1813"}},
		},
	},
	"MS14-023": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2767772", Drop: []string{"CVE-2014-1808"}},
			{KB: "2878284", Drop: []string{"CVE-2014-1808"}},
			{KB: "2878316", Drop: []string{"CVE-2014-1756"}},
			{KB: "2880463", Drop: []string{"CVE-2014-1808"}},
		},
	},
	"MS14-028": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2962073", Drop: []string{"CVE-2014-0256"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2014-0256"}},
		},
	},
	"MS14-029": {
		Supersedes: map[string]supersedesAdjust{
			"2936068": {Add: []string{"2953522", "2961851"}},
			"2964444": {Add: []string{"2953522"}},
		},
		IECumChain: map[string][]string{
			"2953522": {"2961851"},
			"2964358": {"2953522"},
			"2964444": {"2953522"},
		},
	},
	"MS14-035": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-1764", "CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1778", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1791", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1797", "CVE-2014-1800", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777", "CVE-2014-2782"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1778", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1796", "CVE-2014-1797", "CVE-2014-1800", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777", "CVE-2014-2782"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1780", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1797", "CVE-2014-1802", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2767", "CVE-2014-2769", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2782"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1777", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1785", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1797", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-2753", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2773", "CVE-2014-2776"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-1769", "CVE-2014-1774", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1785", "CVE-2014-1788", "CVE-2014-1792", "CVE-2014-1804", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2770", "CVE-2014-2772", "CVE-2014-2773", "CVE-2014-2776"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-1774", "CVE-2014-1781", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1804", "CVE-2014-2754", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2770", "CVE-2014-2773"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2961851": {Add: []string{"2957689"}},
		},
		IECumChain: map[string][]string{
			"2953522": {"2957689"},
			"2957689": {"2963950"},
			"2961851": {"2957689"},
		},
	},
	"MS14-037": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-1763", "CVE-2014-2783", "CVE-2014-2785", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2789", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2795", "CVE-2014-2798", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2803", "CVE-2014-2804", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-1763", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2789", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2795", "CVE-2014-2798", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2803", "CVE-2014-2804", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-1763", "CVE-2014-2785", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2794", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-2785", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-4066"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-2785", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-4066"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-2785", "CVE-2014-2788", "CVE-2014-2791", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2803"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2957689": {Add: []string{"2962872", "2963952"}},
		},
		IECumChain: map[string][]string{
			"2957689": {"2962872"},
			"2962872": {"2963952"},
			"2963950": {"2962872"},
		},
	},
	"MS14-044": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2977315", Drop: []string{"CVE-2014-4061"}},
			{KB: "2977320", Drop: []string{"CVE-2014-1820"}},
			{KB: "2977321", Drop: []string{"CVE-2014-1820"}},
			{Component: "Microsoft SQL Server 2012 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2014-1820"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2716435": {Add: []string{"2977322"}},
		},
	},
	"MS14-045": {CVEAdjustments: []cveAdjustment{{KB: "2993651", Drop: []string{"CVE-2014-4064"}}}},
	"MS14-046": {
		Supersedes: map[string]supersedesAdjust{
			"2844286": {Add: []string{"2937610"}},
			"2844287": {Add: []string{"2937608"}},
			"2844289": {Add: []string{"2966825"}},
			"2898866": {Add: []string{"2966825"}},
			"2898868": {Add: []string{"2966826"}},
		},
	},
	// MS14-051: off-by-3 of CVE-2014-2796 — drop, 2796 already in xlsx.
	// CVE-2014-2799 appears in MS14-052's markdown.
	"MS14-051": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-2784", "CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2819", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4051", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4056", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-2784", "CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4051", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-4057", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-2818", "CVE-2014-2821", "CVE-2014-2824", "CVE-2014-4052", "CVE-2014-4056"}},
			{Remap: map[string]string{"CVE-2014-2799": ""}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2962872": {Add: []string{"2976627", "2977629"}},
		},
		IECumChain: map[string][]string{
			"2962872": {"2976627"},
			"2963952": {"2976627"},
		},
	},
	"MS14-052": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4092", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4098", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4092", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4098", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4086", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4101", "CVE-2014-4102"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-4086", "CVE-2014-4087", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4101"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-4082", "CVE-2014-4084", "CVE-2014-4086", "CVE-2014-4093"}},
		},
		IECumChain: map[string][]string{
			"2976627": {"2977629"},
		},
	},
	"MS14-053": {
		Supersedes: map[string]supersedesAdjust{
			"2756918": {Add: []string{"2973115"}},
		},
	},
	"MS14-055": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2982388", Drop: []string{"CVE-2014-4070", "CVE-2014-4071"}},
			{KB: "2982389", Drop: []string{"CVE-2014-4070", "CVE-2014-4071"}},
			{KB: "2982390", Drop: []string{"CVE-2014-4068", "CVE-2014-4071"}},
			{KB: "2986072", Drop: []string{"CVE-2014-4068", "CVE-2014-4070"}},
			{KB: "2992965", Drop: []string{"CVE-2014-4070", "CVE-2014-4071"}},
		},
	},
	"MS14-056": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-4123", "CVE-2014-4124", "CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4138", "CVE-2014-4140", "CVE-2014-4141"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4138", "CVE-2014-4140", "CVE-2014-4141"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-4126", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4137", "CVE-2014-4138", "CVE-2014-4140"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137", "CVE-2014-4138"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137", "CVE-2014-4138"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-4127", "CVE-2014-4129", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137"}},
		},
		IECumChain: map[string][]string{
			"2976627": {"2987107"},
			"2977629": {"2987107"},
		},
	},
	"MS14-057": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2968292", Drop: []string{"CVE-2014-4073", "CVE-2014-4121"}},
			{KB: "2968294", Drop: []string{"CVE-2014-4073", "CVE-2014-4121"}},
			{KB: "2968295", Drop: []string{"CVE-2014-4073", "CVE-2014-4121"}},
			{KB: "2968296", Drop: []string{"CVE-2014-4073", "CVE-2014-4121"}},
			{KB: "2972098", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972100", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972101", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972103", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972105", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972106", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2972107", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2978041", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2978042", Drop: []string{"CVE-2014-4073", "CVE-2014-4122"}},
			{KB: "2979568", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979570", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979571", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979573", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979574", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979575", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979576", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979577", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
			{KB: "2979578", Drop: []string{"CVE-2014-4121", "CVE-2014-4122"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2729460": {Add: []string{"2972107"}},
		},
	},
	"MS14-064": {CVEAdjustments: []cveAdjustment{{KB: "3006226", Drop: []string{"CVE-2014-6352"}}}},
	"MS14-065": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-6323", "CVE-2014-6337", "CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6346", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350", "CVE-2014-6351"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-6337", "CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6346", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350", "CVE-2014-6351"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-6337", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6345", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-6337", "CVE-2014-6347", "CVE-2014-6349", "CVE-2014-6350"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6344", "CVE-2014-6347", "CVE-2014-6348"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6348", "CVE-2014-6353"}},
		},
		IECumChain: map[string][]string{
			"2987107": {"3003057"},
			"3003057": {"3008923"},
		},
	},
	"MS14-075": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2014-6319", "CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"}},
			{KB: "2986475", Drop: []string{"CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"}},
			{KB: "2996150", Drop: []string{"CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"}},
		},
	},
	"MS14-080": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-6327", "CVE-2014-6328", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6365", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-6327", "CVE-2014-6328", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6365", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6376"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376", "CVE-2014-8966"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6375", "CVE-2014-6376", "CVE-2014-8966"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-6330", "CVE-2014-6366", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-8966"}},
		},
		IECumChain: map[string][]string{
			"3032359": {"3038314"},
		},
	},
	"MS14-081": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2883050", Drop: []string{"CVE-2014-6356"}},
			{KB: "2899518", Drop: []string{"CVE-2014-6356"}},
			{KB: "2899581", Drop: []string{"CVE-2014-6356"}},
			{KB: "2920729", Drop: []string{"CVE-2014-6356"}},
			{KB: "3018888", Drop: []string{"CVE-2014-6356"}},
		},
	},
	"MS14-083": {CVEAdjustments: []cveAdjustment{{KB: "2920791", Drop: []string{"CVE-2014-6361"}}}},
	"MS14-084": {
		Supersedes: map[string]supersedesAdjust{
			"2909210": {Override: []string{"3012176"}},
			"2909212": {Override: []string{"3012172"}},
			"2909213": {Override: []string{"3012168"}},
		},
	},
	"MS15-009": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0043", "CVE-2015-0044", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0054", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0043", "CVE-2015-0044", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0052", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-0018", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0029", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0045", "CVE-2015-0049", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0053", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0037", "CVE-2015-0040", "CVE-2015-0044", "CVE-2015-0045", "CVE-2015-0048", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0053", "CVE-2015-0066", "CVE-2015-0067"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2014-8967", "CVE-2015-0019", "CVE-2015-0021", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0044", "CVE-2015-0045", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0053", "CVE-2015-0067"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3012176": {Override: []string{"3021952"}},
			"3029449": {Add: []string{"3021952"}},
		},
		IECumChain: map[string][]string{
			"3008923": {"3021952"},
			"3021952": {"3034196"},
		},
	},
	"MS15-011": {
		Supersedes: map[string]supersedesAdjust{
			"2536276": {Add: []string{"3000483"}},
		},
	},
	"MS15-012": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2920753", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2920788", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2920791", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2920810", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956058", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956066", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956070", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956073", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2956081", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2956092", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956097", Drop: []string{"CVE-2015-0064", "CVE-2015-0065"}},
			{KB: "2956098", Drop: []string{"CVE-2015-0063", "CVE-2015-0065"}},
			{KB: "2956099", Drop: []string{"CVE-2015-0063"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2827328": {Add: []string{"2920791"}},
		},
		IECumChain: map[string][]string{
			"2956058": {"2956073"},
			"2956097": {"2956098"},
		},
	},
	"MS15-018": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1625", "CVE-2015-1626", "CVE-2015-1627", "CVE-2015-1634"}},
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1626", "CVE-2015-1627"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1626"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1626"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-0056", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1626"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-0056", "CVE-2015-0100", "CVE-2015-1623", "CVE-2015-1626"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-0099", "CVE-2015-0100"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3012176": {Add: []string{"3032359"}},
			"3034196": {Add: []string{"3032359"}},
			"3036197": {Add: []string{"3032359"}},
		},
		IECumChain: map[string][]string{
			"3021952": {"3032359"},
			"3034196": {"3032359"},
		},
	},
	"MS15-020": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3033889", Drop: []string{"CVE-2015-0096"}},
			{KB: "3039066", Drop: []string{"CVE-2015-0081"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2962123": {Add: []string{"3039066"}},
		},
	},
	"MS15-022": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2881068", Drop: []string{"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"}},
			{KB: "2956151", Drop: []string{"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"}},
			{KB: "2956188", Drop: []string{"CVE-2015-0085", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"}},
			{KB: "2956189", Drop: []string{"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"}},
			{KB: "2984939", Drop: []string{"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2956058": {Override: []string{"2956138"}},
		},
	},
	"MS15-023": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2015-0078"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-0078"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-0078"}},
		},
	},
	"MS15-025": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3038680", Drop: []string{"CVE-2015-0073"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-0075"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-0075"}},
		},
	},
	"MS15-032": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2014-6374", "CVE-2015-1652", "CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1661", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1666", "CVE-2015-1667", "CVE-2015-1668"}},
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1667", "CVE-2015-1668"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1667", "CVE-2015-1668"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1668"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-1659", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1668"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-1660"}},
		},
	},
	"MS15-033": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553164", Drop: []string{"CVE-2015-1639", "CVE-2015-1651"}},
			{KB: "2965210", Drop: []string{"CVE-2015-1639"}},
			{KB: "2965215", Drop: []string{"CVE-2015-1639", "CVE-2015-1649", "CVE-2015-1651"}},
			{KB: "2965236", Drop: []string{"CVE-2015-1639", "CVE-2015-1651"}},
			{KB: "2965289", Drop: []string{"CVE-2015-1639", "CVE-2015-1641"}},
			{KB: "3048019", Drop: []string{"CVE-2015-1639"}},
			{KB: "3051737", Drop: []string{"CVE-2015-1641", "CVE-2015-1649", "CVE-2015-1650", "CVE-2015-1651"}},
			{KB: "3055707", Drop: []string{"CVE-2015-1639", "CVE-2015-1641", "CVE-2015-1649", "CVE-2015-1650", "CVE-2015-1651"}},
		},
	},
	"MS15-034": {
		Supersedes: map[string]supersedesAdjust{
			"2829254": {Add: []string{"3042553"}},
		},
	},
	"MS15-035": {
		Supersedes: map[string]supersedesAdjust{
			"2876331": {Add: []string{"3046306"}},
		},
	},
	// MS15-036: 5-digit suffix anomaly; no clean canonical-form candidate —
	// drop.
	"MS15-036": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-1640", "CVE-2015-1653"}},
			{KB: "2965219", Drop: []string{"CVE-2015-1640"}},
			{Remap: map[string]string{"CVE-2015-16453": ""}},
		},
	},
	"MS15-038": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3045999", Drop: []string{"CVE-2015-1643"}},
			{KB: "3049576", Drop: []string{"CVE-2015-1643"}},
		},
	},
	"MS15-043": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2015-1658", "CVE-2015-1684", "CVE-2015-1685", "CVE-2015-1686", "CVE-2015-1688", "CVE-2015-1689", "CVE-2015-1691", "CVE-2015-1692", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1709", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-1658", "CVE-2015-1684", "CVE-2015-1685", "CVE-2015-1686", "CVE-2015-1689", "CVE-2015-1691", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1709", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1689", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1711", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1706", "CVE-2015-1711", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1691", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1717", "CVE-2015-1718"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-1691", "CVE-2015-1708", "CVE-2015-1712"}},
		},
		IECumChain: map[string][]string{
			"3038314": {"3049563"},
		},
	},
	"MS15-044": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2881073", Drop: []string{"CVE-2015-1670"}},
			{KB: "2883029", Drop: []string{"CVE-2015-1670"}},
			{KB: "3039779", Drop: []string{"CVE-2015-1670"}},
			{KB: "3051464", Drop: []string{"CVE-2015-1670"}},
			{KB: "3051465", Drop: []string{"CVE-2015-1670"}},
			{KB: "3051466", Drop: []string{"CVE-2015-1670"}},
			{KB: "3051467", Drop: []string{"CVE-2015-1670"}},
			{KB: "3056819", Drop: []string{"CVE-2015-1670"}},
		},
	},
	"MS15-045": {
		Supersedes: map[string]supersedesAdjust{
			"2974286": {Add: []string{"3046002"}},
		},
	},
	"MS15-046": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2975808", Drop: []string{"CVE-2015-1683"}},
			{KB: "3039736", Drop: []string{"CVE-2015-1683"}},
			{KB: "3039748", Drop: []string{"CVE-2015-1683"}},
			{KB: "3048688", Drop: []string{"CVE-2015-1683"}},
			{KB: "3054833", Drop: []string{"CVE-2015-1683"}},
			{KB: "3054839", Drop: []string{"CVE-2015-1683"}},
			{KB: "3054840", Drop: []string{"CVE-2015-1683"}},
			{KB: "3054843", Drop: []string{"CVE-2015-1683"}},
			{KB: "3057181", Drop: []string{"CVE-2015-1683"}},
			{KB: "3085544", Drop: []string{"CVE-2015-1682"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2826028": {Add: []string{"3054838"}},
			"2826029": {Add: []string{"3054839"}},
			"2956070": {Add: []string{"3054843"}},
			"2956136": {Add: []string{"3054833"}},
			"2956208": {Add: []string{"3054847"}},
			"3051737": {Add: []string{"3048688"}},
			"3054888": {Add: []string{"3085544"}},
		},
	},
	// MS15-048: 5-digit suffix anomaly; no clean canonical-form candidate —
	// drop.
	"MS15-048": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-1672", "CVE-2015-1673"}},
			{KB: "3023211", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023213", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023215", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023217", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023219", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023220", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023221", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023222", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023223", Drop: []string{"CVE-2015-1672"}},
			{KB: "3023224", Drop: []string{"CVE-2015-1672"}},
			{KB: "3032655", Drop: []string{"CVE-2015-1673"}},
			{KB: "3032662", Drop: []string{"CVE-2015-1673"}},
			{KB: "3032663", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035485", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035486", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035487", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035488", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035489", Drop: []string{"CVE-2015-1673"}},
			{KB: "3035490", Drop: []string{"CVE-2015-1673"}},
			{Remap: map[string]string{"CVE-2015-16723": ""}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2804577": {Add: []string{"3035488"}},
			"2863239": {Add: []string{"3035488"}},
		},
	},
	"MS15-053": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3050941", Drop: []string{"CVE-2015-1684"}},
			{KB: "3050945", Drop: []string{"CVE-2015-1684"}},
			{KB: "3050946", Drop: []string{"CVE-2015-1684"}},
		},
	},
	"MS15-055": {
		Supersedes: map[string]supersedesAdjust{
			"3050514": {Add: []string{"3061518"}},
		},
	},
	"MS15-056": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1743", "CVE-2015-1747", "CVE-2015-1748", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755", "CVE-2015-1765"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755", "CVE-2015-1765"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1755", "CVE-2015-1765"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-1687", "CVE-2015-1730", "CVE-2015-1732", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1753", "CVE-2015-1754"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-1687", "CVE-2015-1730", "CVE-2015-1751", "CVE-2015-1754"}},
		},
		IECumChain: map[string][]string{
			"3049563": {"3058515"},
		},
	},
	"MS15-059": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2863812", Drop: []string{"CVE-2015-1770"}},
			{KB: "2863817", Drop: []string{"CVE-2015-1759", "CVE-2015-1770"}},
		},
	},
	"MS15-061": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-1719", "CVE-2015-1720", "CVE-2015-1721", "CVE-2015-1722", "CVE-2015-1723", "CVE-2015-1724", "CVE-2015-1725", "CVE-2015-1726", "CVE-2015-1727", "CVE-2015-1768", "CVE-2015-2360"}}}},
	"MS15-062": {
		Supersedes: map[string]supersedesAdjust{
			"3003381": {Add: []string{"3062577"}},
			"3062577": {Override: []string{"3062577"}},
		},
	},
	"MS15-064": {CVEAdjustments: []cveAdjustment{{Component: "Microsoft Exchange Server 2013 Service Pack 1", Drop: []string{"CVE-2015-2359"}}}},
	"MS15-065": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 6", Drop: []string{"CVE-2015-1729", "CVE-2015-1733", "CVE-2015-1738", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2398", "CVE-2015-2401", "CVE-2015-2402", "CVE-2015-2403", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2414", "CVE-2015-2419", "CVE-2015-2425"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-1729", "CVE-2015-1733", "CVE-2015-1738", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2398", "CVE-2015-2401", "CVE-2015-2403", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2414", "CVE-2015-2419", "CVE-2015-2425"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-1729", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2401", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2419", "CVE-2015-2425"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2389", "CVE-2015-2403", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2419", "CVE-2015-2425"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-1738", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2391", "CVE-2015-2403", "CVE-2015-2425"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-1738", "CVE-2015-2388", "CVE-2015-2391", "CVE-2015-2403"}},
		},
		IECumChain: map[string][]string{
			"3058515": {"3065822"},
		},
	},
	"MS15-068": {CVEAdjustments: []cveAdjustment{{KB: "3046339", Drop: []string{"CVE-2015-2361"}}}},
	"MS15-069": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3061512", Drop: []string{"CVE-2015-2369"}},
			{KB: "3067903", Drop: []string{"CVE-2015-2368"}},
			{KB: "3070738", Drop: []string{"CVE-2015-2369"}},
		},
	},
	"MS15-070": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2837612", Drop: []string{"CVE-2015-2375", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "2965208", Drop: []string{"CVE-2015-2375", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2424"}},
			{KB: "2965209", Drop: []string{"CVE-2015-2375", "CVE-2015-2377", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "2965283", Drop: []string{"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"}},
			{KB: "3054861", Drop: []string{"CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "3054958", Drop: []string{"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "3054963", Drop: []string{"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"}},
			{KB: "3054968", Drop: []string{"CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "3054971", Drop: []string{"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2415", "CVE-2015-2424"}},
			{KB: "3054999", Drop: []string{"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"}},
			{Component: "Microsoft Office for Mac 2011", Drop: []string{"CVE-2015-2375", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"}},
		},
	},
	"MS15-072": {
		Supersedes: map[string]supersedesAdjust{
			"2965155": {Add: []string{"3069392"}},
		},
	},
	"MS15-073": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Windows Server 2003 Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Microsoft Windows Server 2003 x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2015-2363"}},
			{Component: "Windows Server 2003 R2 Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2003 R2 x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-2363"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2366", "CVE-2015-2381", "CVE-2015-2382"}},
		},
	},
	"MS15-079": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-2442", "CVE-2015-2443", "CVE-2015-2444", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-2443", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-2443", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-2446", "CVE-2015-2447"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-2445", "CVE-2015-2448"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2015-2443", "CVE-2015-2444", "CVE-2015-2445", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451", "CVE-2015-2452"}},
		},
		IECumChain: map[string][]string{
			"3065822": {"3078071"},
		},
	},
	"MS15-080": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3078662", Drop: []string{"CVE-2015-2460", "CVE-2015-2463", "CVE-2015-2464"}},
			{KB: "3081436", Drop: []string{"CVE-2015-2432", "CVE-2015-2453", "CVE-2015-2454", "CVE-2015-2460", "CVE-2015-2463", "CVE-2015-2464"}},
		},
	},
	"MS15-081": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553313", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2596650", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2598244", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2477"}},
			{KB: "2687409", Drop: []string{"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2837610", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469"}},
			{KB: "2920691", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2920708", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2965280", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2965310", Drop: []string{"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "2986254", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3039734", Drop: []string{"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3039798", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054816", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2477"}},
			{KB: "3054858", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054876", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054888", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054929", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054960", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054974", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054991", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3054992", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055003", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055029", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055030", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055033", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055037", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055039", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055044", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055051", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055052", Drop: []string{"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055053", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
			{KB: "3055054", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469"}},
			{KB: "3081349", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467"}},
			{KB: "3082420", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470"}},
			{KB: "3085538", Drop: []string{"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"}},
		},
	},
	"MS15-082": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3075220", Drop: []string{"CVE-2015-2473"}},
			{KB: "3075221", Drop: []string{"CVE-2015-2473"}},
		},
	},
	"MS15-091": {
		Supersedes: map[string]supersedesAdjust{
			"3081444": {Override: []string{"3081455"}},
		},
	},
	"MS15-093": {
		IECumChain: map[string][]string{
			"3078071": {"3087985"},
		},
	},
	"MS15-094": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2486", "CVE-2015-2487", "CVE-2015-2489", "CVE-2015-2490", "CVE-2015-2491", "CVE-2015-2492", "CVE-2015-2493", "CVE-2015-2494", "CVE-2015-2496", "CVE-2015-2498", "CVE-2015-2499", "CVE-2015-2500", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2489", "CVE-2015-2491", "CVE-2015-2493", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2489", "CVE-2015-2491", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2489", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2542"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-2489", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2015-2483", "CVE-2015-2487", "CVE-2015-2490", "CVE-2015-2491", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501", "CVE-2015-2541"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3081444": {Override: []string{"3087038"}},
		},
		IECumChain: map[string][]string{
			"3087985": {"3087038"},
		},
	},
	"MS15-095": {
		Supersedes: map[string]supersedesAdjust{
			"3081444": {Add: []string{"3081455"}},
		},
	},
	"MS15-097": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3081455", Drop: []string{"CVE-2015-2510"}},
			{KB: "3087039", Drop: []string{"CVE-2015-2508", "CVE-2015-2510"}},
			{KB: "3087135", Drop: []string{"CVE-2015-2506", "CVE-2015-2507", "CVE-2015-2508", "CVE-2015-2511", "CVE-2015-2512", "CVE-2015-2517", "CVE-2015-2518", "CVE-2015-2527", "CVE-2015-2529", "CVE-2015-2546"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-2529"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2527", "CVE-2015-2529"}},
		},
	},
	"MS15-099": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2522", "CVE-2015-2523", "CVE-2015-2545"}},
			{KB: "2920693", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2545"}},
			{KB: "3054993", Drop: []string{"CVE-2015-2545"}},
			{KB: "3054995", Drop: []string{"CVE-2015-2545"}},
			{KB: "3085502", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2545"}},
			{KB: "3085526", Drop: []string{"CVE-2015-2545"}},
			{KB: "3085543", Drop: []string{"CVE-2015-2545"}},
			{KB: "3085560", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"}},
			{KB: "3085572", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"}},
			{KB: "3085620", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"}},
			{KB: "3085635", Drop: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"}},
			{KB: "3088501", Drop: []string{"CVE-2015-2521", "CVE-2015-2545"}},
			{KB: "3088502", Drop: []string{"CVE-2015-2521", "CVE-2015-2545"}},
		},
	},
	"MS15-101": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 10 for 32-bit Systems", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows 10 for x64-based Systems", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-2526"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2526"}},
		},
	},
	"MS15-102": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3081455", Drop: []string{"CVE-2015-2525"}},
			{KB: "3082089", Drop: []string{"CVE-2015-2525"}},
			{KB: "3084135", Drop: []string{"CVE-2015-2524", "CVE-2015-2528"}},
		},
	},
	"MS15-103": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Exchange Server 2013 Service Pack 1", Drop: []string{"CVE-2015-2543"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3062157": {Add: []string{"3087126"}},
		},
	},
	"MS15-104": {CVEAdjustments: []cveAdjustment{{KB: "3061064", Drop: []string{"CVE-2015-2532"}}}},
	"MS15-106": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6047", "CVE-2015-6048", "CVE-2015-6049", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055", "CVE-2015-6056", "CVE-2015-6059", "CVE-2015-6184"}},
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6047", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055", "CVE-2015-6056", "CVE-2015-6059"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-6042", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6053", "CVE-2015-6056"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6053"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6053"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-6044", "CVE-2015-6050"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6048", "CVE-2015-6050", "CVE-2015-6051"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3081455": {Override: []string{"3097617"}},
		},
		IECumChain: map[string][]string{
			"3081444": {"3097617"},
			"3087038": {"3093983"},
		},
	},
	"MS15-109": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3080446", Drop: []string{"CVE-2015-2548"}},
			{KB: "3097617", Drop: []string{"CVE-2015-2548"}},
		},
	},
	"MS15-110": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-2555", "CVE-2015-2556", "CVE-2015-2557", "CVE-2015-2558", "CVE-2015-6037", "CVE-2015-6039"}},
			{KB: "2553405", Drop: []string{"CVE-2015-6037", "CVE-2015-6039"}},
			{KB: "2596670", Drop: []string{"CVE-2015-6037", "CVE-2015-6039"}},
			{KB: "2920693", Drop: []string{"CVE-2015-2557"}},
			{KB: "3054994", Drop: []string{"CVE-2015-2555", "CVE-2015-6037"}},
			{KB: "3085514", Drop: []string{"CVE-2015-2555", "CVE-2015-2558"}},
			{KB: "3085520", Drop: []string{"CVE-2015-2555", "CVE-2015-2558"}},
			{KB: "3085542", Drop: []string{"CVE-2015-2555", "CVE-2015-2558"}},
			{KB: "3085567", Drop: []string{"CVE-2015-2556", "CVE-2015-6037"}},
			{KB: "3085571", Drop: []string{"CVE-2015-2555", "CVE-2015-2558"}},
			{KB: "3085582", Drop: []string{"CVE-2015-2556"}},
			{KB: "3085583", Drop: []string{"CVE-2015-2557"}},
			{KB: "3085595", Drop: []string{"CVE-2015-2555", "CVE-2015-2558"}},
			{KB: "3085609", Drop: []string{"CVE-2015-2557"}},
			{KB: "3085615", Drop: []string{"CVE-2015-2555", "CVE-2015-2557"}},
			{KB: "3085618", Drop: []string{"CVE-2015-2555", "CVE-2015-2557"}},
			{KB: "3085619", Drop: []string{"CVE-2015-2555", "CVE-2015-2557"}},
			{KB: "3097264", Drop: []string{"CVE-2015-2557"}},
			{KB: "3097266", Drop: []string{"CVE-2015-2557"}},
		},
	},
	"MS15-111": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-2552", "CVE-2015-2554"}},
		},
	},
	"MS15-112": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-2427", "CVE-2015-6064", "CVE-2015-6065", "CVE-2015-6068", "CVE-2015-6069", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6078", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6081", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085", "CVE-2015-6086", "CVE-2015-6088", "CVE-2015-6089"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-2427", "CVE-2015-6064", "CVE-2015-6065", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6078", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085", "CVE-2015-6086", "CVE-2015-6088"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-6064", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-2427", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-2427"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2015-2427", "CVE-2015-6082"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3096448": {Override: []string{"3105213"}},
			"3097617": {Override: []string{"3105213"}},
		},
		IECumChain: map[string][]string{
			"3093983": {"3100773"},
			"3097617": {"3105213"},
		},
	},
	"MS15-116": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2596614", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2596770", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2687406", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2817478", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2878230", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2880506", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2889915", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2899473", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2899516", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2910978", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2920680", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2920698", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2920726", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "2965313", Drop: []string{"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3054793", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3054978", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085477", Drop: []string{"CVE-2015-6038", "CVE-2015-6094"}},
			{KB: "3085511", Drop: []string{"CVE-2015-6038", "CVE-2015-6094"}},
			{KB: "3085548", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085551", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085552", Drop: []string{"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085561", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085584", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085594", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3085614", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101359", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101360", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101364", Drop: []string{"CVE-2015-6093"}},
			{KB: "3101365", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101367", Drop: []string{"CVE-2015-6038", "CVE-2015-6094"}},
			{KB: "3101370", Drop: []string{"CVE-2015-6038", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101371", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101499", Drop: []string{"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"}},
			{KB: "3101506", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101507", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101509", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101510", Drop: []string{"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"}},
			{KB: "3101512", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101513", Drop: []string{"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101514", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101521", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101525", Drop: []string{"CVE-2015-6093", "CVE-2015-6094"}},
			{KB: "3101526", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101529", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101533", Drop: []string{"CVE-2015-6038", "CVE-2015-6094"}},
			{KB: "3101543", Drop: []string{"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"}},
			{KB: "3101544", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101553", Drop: []string{"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101554", Drop: []string{"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101555", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101558", Drop: []string{"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101559", Drop: []string{"CVE-2015-6093", "CVE-2015-6094"}},
			{KB: "3101560", Drop: []string{"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3101564", Drop: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}},
			{KB: "3102924", Drop: []string{"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093"}},
			{KB: "3102925", Drop: []string{"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2553147": {Override: []string{"3101526"}},
			"2553428": {Override: []string{"2899516"}},
			"2687413": {Override: []string{"3101360"}},
			"2956151": {Override: []string{"3085584", "3101499"}},
			"3054929": {Override: []string{"3101370"}},
			"3055029": {Override: []string{"3101370", "3101506"}},
			"3055030": {Override: []string{"3101360", "3101512"}},
			"3055033": {Override: []string{"3085614"}},
			"3085514": {Override: []string{"2965313"}},
			"3085583": {Override: []string{"3054793", "3101371"}},
		},
	},
	"MS15-118": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 10 for 32-bit Systems", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows 10 for x64-based Systems", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-6115"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2015-6115"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2015-6099", "CVE-2015-6115"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2901128": {Add: []string{"3098779"}},
		},
	},
	"MS15-119": {
		Supersedes: map[string]supersedesAdjust{
			"2973408": {Add: []string{"3092601"}},
		},
	},
	"MS15-124": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2015-6083", "CVE-2015-6134", "CVE-2015-6135", "CVE-2015-6136", "CVE-2015-6138", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6144", "CVE-2015-6147", "CVE-2015-6148", "CVE-2015-6149", "CVE-2015-6151", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6156", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162", "CVE-2015-6164"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2015-6134", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6148", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6156", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162", "CVE-2015-6164"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2015-6134", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6153", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2015-6134", "CVE-2015-6141", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6152", "CVE-2015-6162"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2015-6134", "CVE-2015-6141", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6150", "CVE-2015-6152", "CVE-2015-6162", "CVE-2015-6164"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3105211": {Override: []string{"3116900"}},
			"3105213": {Override: []string{"3116869"}},
		},
		IECumChain: map[string][]string{
			"3100773": {"3104002"},
			"3105211": {"3116900"},
			"3105213": {"3116869"},
		},
	},
	"MS15-128": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3116869", Drop: []string{"CVE-2015-6106"}},
			{KB: "3116900", Drop: []string{"CVE-2015-6106", "CVE-2015-6108"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8 for 32-bit Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8 for x64-based Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows RT", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2015-6106"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2015-6106"}},
		},
		RowSplits: []rowSplit{
			{KB: "3116869", Component: "Microsoft .NET Framework 3.5", CVEs: []string{"CVE-2015-6108"}},
		},
	},
	"MS15-131": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3085528", Drop: []string{"CVE-2015-6040", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"}},
			{KB: "3085549", Drop: []string{"CVE-2015-6040", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"}},
			{KB: "3101532", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"}},
			{KB: "3114342", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"}},
			{KB: "3114382", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6177"}},
			{KB: "3114403", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"}},
			{KB: "3114415", Drop: []string{"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"}},
			{KB: "3114422", Drop: []string{"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"}},
			{KB: "3114431", Drop: []string{"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"}},
			{KB: "3114433", Drop: []string{"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"}},
			{KB: "3114457", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"}},
			{KB: "3114458", Drop: []string{"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"}},
			{KB: "3119517", Drop: []string{"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"}},
			{KB: "3119518", Drop: []string{"CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"}},
		},
	},
	"MS15-132": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3116869", Drop: []string{"CVE-2015-6128"}},
			{KB: "3116900", Drop: []string{"CVE-2015-6128"}},
		},
	},
	"MS15-135": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3109094", Drop: []string{"CVE-2015-6175"}},
			{KB: "3116900", Drop: []string{"CVE-2015-6175"}},
		},
	},
	"MS16-001": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 7", Drop: []string{"CVE-2016-0002", "CVE-2016-0005"}},
			{Component: "Internet Explorer 8", Drop: []string{"CVE-2016-0005"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3116869": {Override: []string{"3124266"}},
			"3116900": {Override: []string{"3124263"}},
		},
		IECumChain: map[string][]string{
			"3104002": {"3124275"},
		},
	},
	"MS16-002": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0003", "CVE-2016-0024"}}}},
	// MS16-003: off-by-one of CVE-2016-0002 — remap (0002 not in xlsx).
	// CVE-2016-0003 appears in MS16-002's markdown.
	"MS16-003": {CVEAdjustments: []cveAdjustment{{Remap: map[string]string{"CVE-2016-0003": "CVE-2016-0002"}}}},
	"MS16-004": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-6117", "CVE-2015-6177", "CVE-2016-0010", "CVE-2016-0011", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "2881029", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "2881067", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "2920727", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3039794", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114396", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114402", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114421", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114429", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114482", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114486", Drop: []string{"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "3114489", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114494", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114504", Drop: []string{"CVE-2016-0010"}},
			{KB: "3114511", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114518", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114520", Drop: []string{"CVE-2016-0010"}},
			{KB: "3114526", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114527", Drop: []string{"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "3114540", Drop: []string{"CVE-2016-0010"}},
			{KB: "3114541", Drop: []string{"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "3114546", Drop: []string{"CVE-2015-0012", "CVE-2016-0010", "CVE-2016-0012"}},
			{KB: "3114547", Drop: []string{"CVE-2015-0012", "CVE-2016-0010", "CVE-2016-0012"}},
			{KB: "3114549", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114553", Drop: []string{"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "3114554", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114557", Drop: []string{"CVE-2016-0010", "CVE-2016-0035"}},
			{KB: "3114564", Drop: []string{"CVE-2016-0010"}},
			{KB: "3114569", Drop: []string{"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"}},
			{KB: "3133699", Drop: []string{"CVE-2015-0012", "CVE-2016-0012"}},
			{KB: "3133711", Drop: []string{"CVE-2015-0012", "CVE-2016-0012"}},
		},
	},
	"MS16-005": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3124000", Drop: []string{"CVE-2016-0008"}},
			{KB: "3124001", Drop: []string{"CVE-2016-0009"}},
			{KB: "3124263", Drop: []string{"CVE-2016-0009"}},
			{KB: "3124266", Drop: []string{"CVE-2016-0009"}},
		},
	},
	"MS16-007": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3108664", Drop: []string{"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019"}},
			{KB: "3109560", Drop: []string{"CVE-2016-0014", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"}},
			{KB: "3110329", Drop: []string{"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"}},
			{KB: "3121461", Drop: []string{"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0019", "CVE-2016-0020"}},
			{KB: "3121918", Drop: []string{"CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"}},
			{KB: "3124263", Drop: []string{"CVE-2016-0020"}},
			{KB: "3124266", Drop: []string{"CVE-2016-0020"}},
		},
	},
	"MS16-009": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-0041", "CVE-2016-0062", "CVE-2016-0064"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-0062", "CVE-2016-0071"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-0064", "CVE-2016-0071"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-0064", "CVE-2016-0071"}},
		},
		IECumChain: map[string][]string{
			"3124275": {"3134814"},
		},
	},
	"MS16-010": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 10", Drop: []string{"CVE-2016-0029", "CVE-2016-0031"}},
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 11", Drop: []string{"CVE-2016-0029", "CVE-2016-0030", "CVE-2016-0031"}},
			{Component: "Microsoft Exchange Server 2013 Service Pack 1", Drop: []string{"CVE-2016-0029", "CVE-2016-0031"}},
		},
	},
	"MS16-014": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3126041", Drop: []string{"CVE-2016-0040", "CVE-2016-0041", "CVE-2016-0044"}},
			{KB: "3126434", Drop: []string{"CVE-2016-0040", "CVE-2016-0041", "CVE-2016-0042", "CVE-2016-0049"}},
			{KB: "3126587", Drop: []string{"CVE-2016-0040", "CVE-2016-0042", "CVE-2016-0044", "CVE-2016-0049"}},
			{KB: "3126593", Drop: []string{"CVE-2016-0041", "CVE-2016-0044"}},
			{KB: "3135173", Drop: []string{"CVE-2016-0040", "CVE-2016-0044"}},
			{KB: "3135174", Drop: []string{"CVE-2016-0040", "CVE-2016-0044"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-0040"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-0040"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-0040"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-0040"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-0040", "CVE-2016-0049"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-0042", "CVE-2016-0049"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3121918": {Override: []string{"3126041"}},
		},
	},
	"MS16-015": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3039768", Drop: []string{"CVE-2016-0039"}},
			{KB: "3114335", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"}},
			{KB: "3114338", Drop: []string{"CVE-2016-0054"}},
			{KB: "3114401", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"}},
			{KB: "3114407", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"}},
			{KB: "3114432", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"}},
			{KB: "3114481", Drop: []string{"CVE-2016-0054"}},
			{KB: "3114548", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114698", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114702", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114724", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114733", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"}},
			{KB: "3114734", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114741", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114742", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0054", "CVE-2016-0056"}},
			{KB: "3114745", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114747", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114748", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114752", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114755", Drop: []string{"CVE-2016-0054", "CVE-2016-0055"}},
			{KB: "3114759", Drop: []string{"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3114773", Drop: []string{"CVE-2016-0054", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3134241", Drop: []string{"CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{KB: "3137721", Drop: []string{"CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-0022", "CVE-2016-0052"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-0022", "CVE-2016-0052"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-0054"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-0054"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3133699": {Override: []string{"3137721"}},
		},
	},
	"MS16-018": {
		Supersedes: map[string]supersedesAdjust{
			"3124001": {Add: []string{"3134214"}},
		},
	},
	"MS16-022": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967", "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971", "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975", "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979", "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983", "CVE-2016-0984", "CVE-2016-0985"}}}},
	"MS16-023": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-0102", "CVE-2016-0103", "CVE-2016-0104", "CVE-2016-0106", "CVE-2016-0108", "CVE-2016-0109", "CVE-2016-0110", "CVE-2016-0114"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-0102", "CVE-2016-0103", "CVE-2016-0106", "CVE-2016-0108", "CVE-2016-0109", "CVE-2016-0114"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-0104"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-0103", "CVE-2016-0104", "CVE-2016-0106", "CVE-2016-0113", "CVE-2016-0114"}},
		},
		IECumChain: map[string][]string{
			"3134814": {"3139929"},
			"3135173": {"3140768"},
			"3135174": {"3140745"},
		},
	},
	"MS16-027": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3138910", Drop: []string{"CVE-2016-0098"}},
			{KB: "3138962", Drop: []string{"CVE-2016-0101"}},
			{KB: "3140768", Drop: []string{"CVE-2016-0098"}},
		},
	},
	"MS16-028": {CVEAdjustments: []cveAdjustment{{KB: "3137513", Drop: []string{"CVE-2016-0118"}}}},
	"MS16-029": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2956063", Drop: []string{"CVE-2016-0021", "CVE-2016-0134"}},
			{KB: "2956110", Drop: []string{"CVE-2016-0021", "CVE-2016-0134"}},
			{KB: "3039746", Drop: []string{"CVE-2016-0021", "CVE-2016-0134"}},
			{KB: "3114414", Drop: []string{"CVE-2016-0057", "CVE-2016-0134"}},
			{KB: "3114426", Drop: []string{"CVE-2016-0057", "CVE-2016-0134"}},
			{KB: "3114690", Drop: []string{"CVE-2016-0021", "CVE-2016-0134"}},
			{KB: "3114812", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114824", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114833", Drop: []string{"CVE-2016-0057", "CVE-2016-0134"}},
			{KB: "3114855", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114873", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114878", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114900", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3114901", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3138327", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
			{KB: "3138328", Drop: []string{"CVE-2016-0021", "CVE-2016-0057"}},
		},
	},
	"MS16-033": {
		IECumChain: map[string][]string{
			"3140745": {"3147461"},
		},
	},
	"MS16-035": {
		Supersedes: map[string]supersedesAdjust{
			"3099862": {Override: []string{"3135988"}},
		},
	},
	"MS16-036": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-8652", "CVE-2015-8655", "CVE-2015-8658", "CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963", "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989", "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0993", "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-1001", "CVE-2016-1005", "CVE-2016-1010"}}}},
	"MS16-037": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-0160", "CVE-2016-0164", "CVE-2016-0166"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-0159", "CVE-2016-0160", "CVE-2016-0166"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-0159"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-0159", "CVE-2016-0164"}},
		},
		IECumChain: map[string][]string{
			"3139929": {"3148198"},
			"3140768": {"3147458"},
		},
	},
	"MS16-039": {
		CVEAdjustments: []cveAdjustment{
			{KB: "4038788", Drop: []string{"CVE-2016-0143", "CVE-2016-0145", "CVE-2016-0167"}},
			{KB: "4093112", Drop: []string{"CVE-2016-0145", "CVE-2016-0165", "CVE-2016-0167"}},
		},
	},
	"MS16-042": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3114871", Drop: []string{"CVE-2016-0127"}},
			{KB: "3114888", Drop: []string{"CVE-2016-0127"}},
			{KB: "3114892", Drop: []string{"CVE-2016-0127", "CVE-2016-0139"}},
			{KB: "3114895", Drop: []string{"CVE-2016-0127", "CVE-2016-0139"}},
			{KB: "3114897", Drop: []string{"CVE-2016-0127"}},
			{KB: "3114898", Drop: []string{"CVE-2016-0127", "CVE-2016-0136"}},
			{KB: "3114927", Drop: []string{"CVE-2016-0136"}},
			{KB: "3114934", Drop: []string{"CVE-2016-0136"}},
			{KB: "3114937", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114947", Drop: []string{"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114964", Drop: []string{"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114982", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114983", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114987", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114988", Drop: []string{"CVE-2016-0136"}},
			{KB: "3114990", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114993", Drop: []string{"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3114994", Drop: []string{"CVE-2016-0136"}},
			{KB: "3142577", Drop: []string{"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"}},
			{KB: "3154208", Drop: []string{"CVE-2016-0122", "CVE-2016-0127", "CVE-2016-0136"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3138327": {Add: []string{"3142577"}},
			"3138328": {Add: []string{"3154208"}},
		},
	},
	"MS16-045": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-0090"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-0090"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-0090"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-0090"}},
		},
	},
	"MS16-050": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013", "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017", "CVE-2016-1018", "CVE-2016-1019"}}}},
	"MS16-051": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-0188", "CVE-2016-0194"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-0188"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-0188"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3148198": {Add: []string{"3154070"}},
		},
		IECumChain: map[string][]string{
			"3147458": {"3156421"},
			"3147461": {"3156387"},
			"3148198": {"3154070"},
		},
	},
	"MS16-053": {CVEAdjustments: []cveAdjustment{{KB: "3158991", Drop: []string{"CVE-2016-0187"}}}},
	"MS16-054": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2984938", Drop: []string{"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "2984943", Drop: []string{"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "3054984", Drop: []string{"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "3101520", Drop: []string{"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "3114893", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"}},
			{KB: "3115016", Drop: []string{"CVE-2016-0140", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "3115025", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3115094", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3115103", Drop: []string{"CVE-2016-0140", "CVE-2016-0183", "CVE-2016-0198"}},
			{KB: "3115115", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3115116", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3115121", Drop: []string{"CVE-2016-0126", "CVE-2016-0140"}},
			{KB: "3115123", Drop: []string{"CVE-2016-0126", "CVE-2016-0140"}},
			{KB: "3115132", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3115464", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"}},
			{KB: "3115465", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"}},
			{KB: "3115479", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"}},
			{KB: "3115480", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"}},
			{KB: "3155776", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
			{KB: "3155777", Drop: []string{"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2760585": {Add: []string{"2984943"}},
			"2760591": {Add: []string{"2984938"}},
			"3054841": {Add: []string{"3101520"}, Override: []string{"3054984"}},
			"3054848": {Add: []string{"3054984"}, Override: []string{"3115121"}},
			"3114486": {Add: []string{"3115016"}, Override: []string{"3115025"}},
			"3114855": {Add: []string{"3115094"}, Override: []string{"3115103"}},
			"3114937": {Override: []string{"3115016"}},
			"3114982": {Add: []string{"3115115"}, Override: []string{"3155776"}},
			"3114983": {Add: []string{"3115116"}, Override: []string{"2984938"}},
			"3114987": {Add: []string{"3115132"}, Override: []string{"3155777"}},
			"3114990": {Add: []string{"3115121"}, Override: []string{"2984943", "3115116"}},
			"3114993": {Add: []string{"3115123"}, Override: []string{"3101520"}},
			"3115309": {Add: []string{"3115464"}},
			"3142577": {Add: []string{"3155777"}, Override: []string{"3115094"}},
			"3154208": {Add: []string{"3155776"}, Override: []string{"3115094"}},
		},
	},
	"MS16-055": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3156013", Drop: []string{"CVE-2016-0184", "CVE-2016-0195"}},
			{KB: "3156016", Drop: []string{"CVE-2016-0168", "CVE-2016-0169", "CVE-2016-0170", "CVE-2016-0195"}},
			{KB: "3156019", Drop: []string{"CVE-2016-0168", "CVE-2016-0169", "CVE-2016-0170", "CVE-2016-0184"}},
		},
	},
	"MS16-058": {
		Supersedes: map[string]supersedesAdjust{
			"982666": {Add: []string{"3141083"}},
		},
	},
	"MS16-062": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3153199", Drop: []string{"CVE-2016-0176", "CVE-2016-0197"}},
			{KB: "3156017", Drop: []string{"CVE-2016-0171", "CVE-2016-0173", "CVE-2016-0174", "CVE-2016-0175", "CVE-2016-0196"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-0176"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-0176"}},
		},
	},
	"MS16-063": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-3202", "CVE-2016-3210"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-3210"}},
		},
		IECumChain: map[string][]string{
			"3154070": {"3160005"},
			"3156387": {"3163017"},
			"3156421": {"3163018"},
		},
	},
	"MS16-064": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099", "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103", "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107", "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108", "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112", "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116", "CVE-2016-4117"}}}},
	"MS16-067": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-0190"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-0190"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-0190"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-0190"}},
		},
	},
	// MS16-068's CVE summary table documents CVE-2016-3215 as
	// "Critical / RCE (Only Windows 10 Version 1511 is affected)" in
	// natural-language narrowing rather than a per-CVE matrix table —
	// so gen_static_map.py's Format A parser, which looks for explicit
	// "Not applicable" cells, did not surface this NA. The same xlsx
	// row of KB3163017 (Win 10 RTM Edge cumulative) appears in both
	// MS16-073 and MS16-080 where the per-CVE matrix tables *do* mark
	// it NA, so the legacy global lookup propagated the filter to
	// MS16-068's rows too. Restated here explicitly under MS16-068's
	// own amendments to preserve the filter under per-bulletin scope.
	"MS16-068": {CVEAdjustments: []cveAdjustment{{KB: "3163017", Drop: []string{"CVE-2016-3215"}}}},
	"MS16-070": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2596915", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "2999465", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "3114740", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "3114872", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "3115020", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "3115041", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"}},
			{KB: "3115107", Drop: []string{"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115111", Drop: []string{"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115130", Drop: []string{"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115134", Drop: []string{"CVE-2016-3234"}},
			{KB: "3115144", Drop: []string{"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115173", Drop: []string{"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115182", Drop: []string{"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3115187", Drop: []string{"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3235"}},
			{KB: "3115194", Drop: []string{"CVE-2016-3233", "CVE-2016-3235"}},
			{KB: "3115195", Drop: []string{"CVE-2016-3233", "CVE-2016-3235"}},
			{KB: "3115198", Drop: []string{"CVE-2016-3233", "CVE-2016-3235"}},
			{KB: "3115243", Drop: []string{"CVE-2016-3233", "CVE-2016-3235"}},
			{KB: "3165796", Drop: []string{"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"}},
			{KB: "3165798", Drop: []string{"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2687505": {Override: []string{"2596915"}},
			"3114402": {Override: []string{"3115130"}},
			"3114421": {Add: []string{"3114740"}, Override: []string{"3115107"}},
			"3114489": {Override: []string{"3115243"}},
			"3114511": {Override: []string{"3115144"}},
			"3114527": {Add: []string{"3115144"}},
			"3114888": {Override: []string{"3115170", "3115198"}},
			"3114892": {Add: []string{"3115107"}},
			"3114895": {Add: []string{"3115111"}, Override: []string{"3165798"}},
			"3114927": {Add: []string{"3115014"}},
			"3114934": {Add: []string{"3115170"}},
			"3115025": {Override: []string{"3115020"}},
			"3115094": {Override: []string{"3115041"}},
			"3115115": {Add: []string{"3115194"}, Override: []string{"3115111"}},
			"3115116": {Add: []string{"3115195"}, Override: []string{"3114740", "3115196"}},
			"3115117": {Add: []string{"3115196"}},
			"3115121": {Override: []string{"3115014", "3115195", "3115244"}},
			"3115123": {Override: []string{"3114872"}},
			"3115124": {Add: []string{"3115244"}},
			"3115132": {Add: []string{"3115187"}, Override: []string{"3115194"}},
		},
	},
	"MS16-073": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3161664", Drop: []string{"CVE-2016-3232"}},
			{KB: "3163017", Drop: []string{"CVE-2016-3232"}},
			{KB: "3163018", Drop: []string{"CVE-2016-3232"}},
			{KB: "3164294", Drop: []string{"CVE-2016-3218", "CVE-2016-3221"}},
		},
	},
	"MS16-074": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3164033", Drop: []string{"CVE-2016-3216", "CVE-2016-3219"}},
			{KB: "3164035", Drop: []string{"CVE-2016-3219", "CVE-2016-3220"}},
		},
	},
	"MS16-077": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3213", "CVE-2016-3236", "CVE-2016-3299"}}}},
	// MS16-079: cross-year mis-tag of CVE-2015-6015 — remap (6015 not in
	// xlsx). CVE-2015-6016 not in any MS16 bulletin.
	"MS16-079": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3151086", Drop: []string{"CVE-2016-0028"}},
			{KB: "3151097", Drop: []string{"CVE-2016-0028"}},
			{Remap: map[string]string{"CVE-2015-6016": "CVE-2015-6015"}},
		},
	},
	"MS16-080": {CVEAdjustments: []cveAdjustment{{KB: "3163017", Drop: []string{"CVE-2016-3215"}}}},
	"MS16-083": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4121", "CVE-2016-4122", "CVE-2016-4123", "CVE-2016-4124", "CVE-2016-4125", "CVE-2016-4126", "CVE-2016-4127", "CVE-2016-4128", "CVE-2016-4129", "CVE-2016-4130", "CVE-2016-4131", "CVE-2016-4132", "CVE-2016-4133", "CVE-2016-4134", "CVE-2016-4135", "CVE-2016-4136", "CVE-2016-4137", "CVE-2016-4138", "CVE-2016-4139", "CVE-2016-4140", "CVE-2016-4141", "CVE-2016-4142", "CVE-2016-4143", "CVE-2016-4144", "CVE-2016-4145", "CVE-2016-4146", "CVE-2016-4147", "CVE-2016-4148", "CVE-2016-4149", "CVE-2016-4150", "CVE-2016-4151", "CVE-2016-4152", "CVE-2016-4153", "CVE-2016-4154", "CVE-2016-4155", "CVE-2016-4156", "CVE-2016-4166", "CVE-2016-4171"}}}},
	// MS16-084: Microsoft retracted CVE-2016-3276 in the V1.1 (2017-03-17)
	// revision — "Removed CVE-2016-3276 ... because IE 9/10/11 are not
	// affected." Drop, no correction.
	"MS16-084": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2016-3204", "CVE-2016-3240", "CVE-2016-3241", "CVE-2016-3242", "CVE-2016-3243", "CVE-2016-3245", "CVE-2016-3248", "CVE-2016-3259", "CVE-2016-3260", "CVE-2016-3261", "CVE-2016-3264", "CVE-2016-3273", "CVE-2016-3274", "CVE-2016-3277"}},
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-3243", "CVE-2016-3260", "CVE-2016-3261", "CVE-2016-3277"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-3260", "CVE-2016-3261"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-3245"}},
			{Remap: map[string]string{"CVE-2016-3276": ""}},
		},
		IECumChain: map[string][]string{
			"3160005": {"3170106"},
		},
	},
	"MS16-088": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3115114", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115118", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115246", Drop: []string{"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115254", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115259", Drop: []string{"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115262", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115272", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115279", Drop: []string{"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115285", Drop: []string{"CVE-2016-3279", "CVE-2016-3281"}},
			{KB: "3115289", Drop: []string{"CVE-2016-3279", "CVE-2016-3281"}},
			{KB: "3115292", Drop: []string{"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115299", Drop: []string{"CVE-2016-3279", "CVE-2016-3281"}},
			{KB: "3115301", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115306", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115308", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115309", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115311", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115315", Drop: []string{"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115317", Drop: []string{"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115322", Drop: []string{"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"}},
			{KB: "3115386", Drop: []string{"CVE-2016-3279", "CVE-2016-3281"}},
			{KB: "3115393", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"}},
			{KB: "3115395", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3284"}},
			{KB: "3170460", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3283"}},
			{KB: "3170463", Drop: []string{"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3283"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-3284"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-3284"}},
		},
	},
	"MS16-090": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-3250"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-3250"}},
		},
	},
	"MS16-092": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3169704", Drop: []string{"CVE-2016-3258"}},
			{KB: "3170377", Drop: []string{"CVE-2016-3272"}},
		},
	},
	"MS16-093": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4182", "CVE-2016-4185", "CVE-2016-4188", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249"}}}},
	"MS16-095": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-3288", "CVE-2016-3289", "CVE-2016-3290", "CVE-2016-3321", "CVE-2016-3322"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-3288", "CVE-2016-3289", "CVE-2016-3290", "CVE-2016-3322"}},
		},
		IECumChain: map[string][]string{
			"3170106": {"3175443"},
		},
	},
	"MS16-096": {
		IECumChain: map[string][]string{
			"3163912": {"3176492"},
			"3172985": {"3176493"},
		},
	},
	"MS16-097": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3176492", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{KB: "3176493", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{KB: "3176495", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-3303", "CVE-2016-3304"}},
		},
	},
	"MS16-099": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3114340", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"}},
			{KB: "3114400", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"}},
			{KB: "3114442", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"}},
			{KB: "3114456", Drop: []string{"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3114869", Drop: []string{"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3114885", Drop: []string{"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3114893", Drop: []string{"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115256", Drop: []string{"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115415", Drop: []string{"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115419", Drop: []string{"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115427", Drop: []string{"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115439", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115449", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115465", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"}},
			{KB: "3115468", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"}},
			{KB: "3115471", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"}},
			{KB: "3115479", Drop: []string{"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"}},
			{KB: "3115480", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"}},
			{KB: "3179162", Drop: []string{"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"}},
			{KB: "3179163", Drop: []string{"CVE-2016-3318"}},
			{Component: "Microsoft OneNote 2016 for Mac", Drop: []string{"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-3315"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3114742": {Add: []string{"3114893"}},
			"3115311": {Add: []string{"3115465"}},
			"3115393": {Add: []string{"3115480"}},
			"3115395": {Add: []string{"3115479"}},
		},
	},
	"MS16-101": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3167679", Drop: []string{"CVE-2016-3300"}},
			{KB: "3177108", Drop: []string{"CVE-2016-3237"}},
			{KB: "3185330", Drop: []string{"CVE-2016-3300"}},
			{KB: "3185331", Drop: []string{"CVE-2016-3300"}},
			{KB: "3185332", Drop: []string{"CVE-2016-3300"}},
			{KB: "3192391", Drop: []string{"CVE-2016-3300"}},
			{KB: "3192392", Drop: []string{"CVE-2016-3300"}},
			{KB: "3192393", Drop: []string{"CVE-2016-3300"}},
			{KB: "3192440", Drop: []string{"CVE-2016-3300"}},
			{KB: "3192441", Drop: []string{"CVE-2016-3300"}},
			{KB: "3194798", Drop: []string{"CVE-2016-3300"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3175024": {Add: []string{"3185330"}},
		},
		IECumChain: map[string][]string{
			"3170106": {"3192391", "3192393"},
			"3175443": {"3185319"},
			"3176492": {"3185611"},
			"3176493": {"3185614"},
			"3176495": {"3189866"},
			"3185319": {"3185331", "3192391", "3192392"},
			"3185611": {"3192440"},
			"3185614": {"3192441"},
			"3189866": {"3194798"},
		},
	},
	"MS16-102": {
		Supersedes: map[string]supersedesAdjust{
			"3157569": {Add: []string{"3175887"}},
		},
	},
	"MS16-104": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3292", "CVE-2016-3295", "CVE-2016-3325"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3325"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-3325"}},
		},
	},
	"MS16-105": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3294", "CVE-2016-3295", "CVE-2016-3297", "CVE-2016-3325", "CVE-2016-3330", "CVE-2016-3350", "CVE-2016-3351", "CVE-2016-3370", "CVE-2016-3374", "CVE-2016-3377"}}}},
	"MS16-106": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3185611", Drop: []string{"CVE-2016-3356"}},
			{KB: "3185614", Drop: []string{"CVE-2016-3356"}},
			{KB: "3185911", Drop: []string{"CVE-2016-3356"}},
			{KB: "3189866", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-3349"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-3349"}},
		},
	},
	"MS16-107": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2553432", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "2597974", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3054862", Drop: []string{"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"}},
			{KB: "3054969", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3114744", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3115112", Drop: []string{"CVE-2016-3357", "CVE-2016-3360"}},
			{KB: "3115119", Drop: []string{"CVE-2016-3357", "CVE-2016-3360"}},
			{KB: "3115169", Drop: []string{"CVE-2016-3360"}},
			{KB: "3115443", Drop: []string{"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3362", "CVE-2016-3365"}},
			{KB: "3115459", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3115462", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3115463", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3115466", Drop: []string{"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3362", "CVE-2016-3365"}},
			{KB: "3115467", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3115472", Drop: []string{"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"}},
			{KB: "3115487", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118268", Drop: []string{"CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118270", Drop: []string{"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"}},
			{KB: "3118280", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"}},
			{KB: "3118284", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3118290", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3118292", Drop: []string{"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118293", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"}},
			{KB: "3118297", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118299", Drop: []string{"CVE-2016-3357", "CVE-2016-3360"}},
			{KB: "3118300", Drop: []string{"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118303", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"}},
			{KB: "3118309", Drop: []string{"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3118313", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"}},
			{KB: "3118316", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3364", "CVE-2016-3366"}},
			{KB: "3185852", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3186805", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"}},
			{KB: "3186807", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3366"}},
			{Component: "Microsoft Office 2013 RT Service Pack 1", Drop: []string{"CVE-2016-0137", "CVE-2016-0141"}},
			{Component: "Microsoft Office 2013 Service Pack 1 (32-bit editions)", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"}},
			{Component: "Microsoft Office 2013 Service Pack 1 (32-bit editions)", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"}},
			{Component: "Microsoft Office 2013 Service Pack 1 (64-bit editions)", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"}},
			{Component: "Microsoft Office 2013 Service Pack 1 (64-bit editions)", Drop: []string{"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"}},
			{Component: "Microsoft Outlook 2016 for Mac", Drop: []string{"CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3360"}},
			{Component: "Microsoft PowerPoint 2016 for Mac", Drop: []string{"CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3366"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3366"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3115118": {Override: []string{"3115487", "3118280"}},
			"3115254": {Add: []string{"3115487"}},
			"3115262": {Override: []string{"3118268"}},
			"3115272": {Override: []string{"3118292"}},
			"3115452": {Override: []string{"3118284"}},
		},
	},
	// MS16-108 covers the Oracle Outside In Libraries Vulnerabilities
	// per Oracle Critical Patch Update Advisory - July 2016. The CVEs
	// are listed inline-grouped by severity (RCE / Info Disclosure /
	// DoS) in the bulletin body rather than in per-CVE section
	// headings, which is why the harvester sees them once each in
	// markdown.
	"MS16-108": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2015-6014", "CVE-2016-0138", "CVE-2016-3378", "CVE-2016-3379", "CVE-2016-3574", "CVE-2016-3575", "CVE-2016-3576", "CVE-2016-3577", "CVE-2016-3578", "CVE-2016-3579", "CVE-2016-3580", "CVE-2016-3581", "CVE-2016-3582", "CVE-2016-3583", "CVE-2016-3590", "CVE-2016-3591", "CVE-2016-3592", "CVE-2016-3593", "CVE-2016-3594", "CVE-2016-3595", "CVE-2016-3596"}},
			{KB: "3184711", Drop: []string{"CVE-2016-3378", "CVE-2016-3379"}},
			{KB: "3184728", Drop: []string{"CVE-2016-3378", "CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 12", Drop: []string{"CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 12", Drop: []string{"CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 13", Drop: []string{"CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Cumulative Update 13", Drop: []string{"CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Service Pack 1", Drop: []string{"CVE-2016-3379"}},
			{Component: "Microsoft Exchange Server 2013 Service Pack 1", Drop: []string{"CVE-2016-3379"}},
		},
	},
	"MS16-110": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3184471", Drop: []string{"CVE-2016-3346", "CVE-2016-3352", "CVE-2016-3369"}},
			{KB: "3187754", Drop: []string{"CVE-2016-3346", "CVE-2016-3368", "CVE-2016-3369"}},
			{KB: "3189866", Drop: []string{"CVE-2016-3369"}},
		},
	},
	"MS16-111": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3185611", Drop: []string{"CVE-2016-3372"}},
			{KB: "3185614", Drop: []string{"CVE-2016-3372"}},
			{KB: "3189866", Drop: []string{"CVE-2016-3372"}},
			{KB: "4025342", Drop: []string{"CVE-2016-3306", "CVE-2016-3371", "CVE-2016-3372", "CVE-2016-3373"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 R2", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
			{Component: "Windows Server 2012 R2 (Server Core installation)", Drop: []string{"CVE-2016-3372"}},
		},
	},
	"MS16-117": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4271", "CVE-2016-4272", "CVE-2016-4274", "CVE-2016-4275", "CVE-2016-4276", "CVE-2016-4277", "CVE-2016-4278", "CVE-2016-4279", "CVE-2016-4280", "CVE-2016-4281", "CVE-2016-4282", "CVE-2016-4283", "CVE-2016-4284", "CVE-2016-4285", "CVE-2016-4287", "CVE-2016-6921", "CVE-2016-6922", "CVE-2016-6923", "CVE-2016-6924", "CVE-2016-6925", "CVE-2016-6926", "CVE-2016-6927", "CVE-2016-6929", "CVE-2016-6930", "CVE-2016-6931", "CVE-2016-6932"}}}},
	"MS16-118": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-3331", "CVE-2016-3383", "CVE-2016-3387", "CVE-2016-3388", "CVE-2016-3390"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-3331", "CVE-2016-3390"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2016-3331"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-3383"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3185319": {Add: []string{"3185330", "3185331", "3185332"}},
		},
		IECumChain: map[string][]string{
			"3170106": {"3191492"},
		},
	},
	"MS16-120": {
		Supersedes: map[string]supersedesAdjust{
			"3142041": {Add: []string{"3188735"}},
			"3142042": {Add: []string{"3188740"}},
			"3142043": {Add: []string{"3188741"}},
			"3142045": {Add: []string{"3188743"}},
		},
	},
	"MS16-121": {
		Supersedes: map[string]supersedesAdjust{
			"3115443": {Add: []string{"3118352"}},
			"3115466": {Add: []string{"3118377"}},
			"3115472": {Add: []string{"3118384"}},
			"3118270": {Add: []string{"3118360"}},
			"3118299": {Add: []string{"3127897"}},
		},
	},
	"MS16-123": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2016-3266", "CVE-2016-3341", "CVE-2016-3376", "CVE-2016-7185", "CVE-2016-7191", "CVE-2016-7211"}},
			{KB: "3183431", Drop: []string{"CVE-2016-3266", "CVE-2016-3341", "CVE-2016-3376", "CVE-2016-7211"}},
			{KB: "3185330", Drop: []string{"CVE-2016-3341"}},
			{KB: "3191203", Drop: []string{"CVE-2016-3341", "CVE-2016-7185"}},
			{KB: "3192391", Drop: []string{"CVE-2016-3341"}},
		},
	},
	"MS16-124": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3185330", Drop: []string{"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079"}},
			{KB: "3185331", Drop: []string{"CVE-2016-0079"}},
			{KB: "3185332", Drop: []string{"CVE-2016-0079"}},
			{KB: "3191256", Drop: []string{"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079"}},
			{KB: "3192391", Drop: []string{"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079"}},
			{KB: "3192392", Drop: []string{"CVE-2016-0079"}},
			{KB: "3192393", Drop: []string{"CVE-2016-0079"}},
		},
	},
	"MS16-127": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982", "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986", "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992"}}}},
	"MS16-128": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7855"}}}},
	"MS16-129": {
		IECumChain: map[string][]string{
			"3192440": {"3198585"},
			"3192441": {"3198586"},
			"3194798": {"3200970"},
		},
	},
	"MS16-130": {
		Supersedes: map[string]supersedesAdjust{
			"3033889": {Override: []string{"3193418"}},
			"3184122": {Override: []string{"3196718"}},
		},
		IECumChain: map[string][]string{
			"3185319": {"3197867", "3197876"},
			"3185331": {"3197874"},
			"3192391": {"3197867"},
			"3192392": {"3197873"},
		},
	},
	"MS16-131": {
		Supersedes: map[string]supersedesAdjust{
			"3190847": {Override: []string{"3198218"}},
		},
	},
	"MS16-132": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3197867", Drop: []string{"CVE-2016-7217"}},
			{KB: "3197868", Drop: []string{"CVE-2016-7217"}},
			{KB: "3203859", Drop: []string{"CVE-2016-7205", "CVE-2016-7217"}},
		},
	},
	"MS16-133": {
		CVEAdjustments: []cveAdjustment{
			{KB: "2986253", Drop: []string{"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"}},
			{KB: "3115120", Drop: []string{"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"}},
			{KB: "3115135", Drop: []string{"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"}},
			{KB: "3115153", Drop: []string{"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"}},
			{KB: "3118378", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7232"}},
			{KB: "3118381", Drop: []string{"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7234"}},
			{KB: "3118382", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7232"}},
			{KB: "3118390", Drop: []string{"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232", "CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3118395", Drop: []string{"CVE-2016-7230", "CVE-2016-7232"}},
			{KB: "3118396", Drop: []string{"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7245"}},
			{KB: "3127889", Drop: []string{"CVE-2016-7230", "CVE-2016-7232"}},
			{KB: "3127893", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7230", "CVE-2016-7232"}},
			{KB: "3127904", Drop: []string{"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232"}},
			{KB: "3127921", Drop: []string{"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232"}},
			{KB: "3127927", Drop: []string{"CVE-2016-7230", "CVE-2016-7236"}},
			{KB: "3127929", Drop: []string{"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7236"}},
			{KB: "3127932", Drop: []string{"CVE-2016-7233", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3127948", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3127949", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3127950", Drop: []string{"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7236"}},
			{KB: "3127951", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3127953", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3127954", Drop: []string{"CVE-2016-7236"}},
			{KB: "3127962", Drop: []string{"CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3198798", Drop: []string{"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232", "CVE-2016-7233", "CVE-2016-7235", "CVE-2016-7244", "CVE-2016-7245"}},
			{KB: "3198807", Drop: []string{"CVE-2016-7230", "CVE-2016-7244", "CVE-2016-7245"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-7234"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-7234"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-7232"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-7232"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-7236"}},
			{Component: "Microsoft Word 2016 for Mac", Drop: []string{"CVE-2016-7236"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7236"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7236"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3118307": {Override: []string{"3198798"}},
		},
	},
	"MS16-134": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0026", "CVE-2016-3332", "CVE-2016-3333", "CVE-2016-3334", "CVE-2016-3335", "CVE-2016-3338", "CVE-2016-3340", "CVE-2016-3342", "CVE-2016-3343", "CVE-2016-7184"}}}},
	"MS16-135": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3194371", Drop: []string{"CVE-2016-7214", "CVE-2016-7215", "CVE-2016-7246"}},
			{KB: "3198234", Drop: []string{"CVE-2016-7218", "CVE-2016-7246"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-7255"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2016-7255"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3177725": {Override: []string{"3194371"}},
			"3184122": {Add: []string{"3194371"}},
		},
	},
	"MS16-136": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3194714", Drop: []string{"CVE-2016-7249", "CVE-2016-7251", "CVE-2016-7252", "CVE-2016-7254"}},
			{KB: "3194716", Drop: []string{"CVE-2016-7253", "CVE-2016-7254"}},
			{KB: "3194719", Drop: []string{"CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252"}},
			{KB: "3194720", Drop: []string{"CVE-2016-7249", "CVE-2016-7251", "CVE-2016-7252", "CVE-2016-7254"}},
			{KB: "3194721", Drop: []string{"CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252"}},
		},
	},
	"MS16-137": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2016-7220", "CVE-2016-7237", "CVE-2016-7238"}},
			{KB: "3197867", Drop: []string{"CVE-2016-7220"}},
			{KB: "3197868", Drop: []string{"CVE-2016-7220"}},
			{KB: "3197873", Drop: []string{"CVE-2016-7220"}},
			{KB: "3197874", Drop: []string{"CVE-2016-7220"}},
			{KB: "3197876", Drop: []string{"CVE-2016-7220"}},
			{KB: "3197877", Drop: []string{"CVE-2016-7220"}},
			{KB: "3198510", Drop: []string{"CVE-2016-7220"}},
			{KB: "3198586", Drop: []string{"CVE-2016-7220"}},
			{KB: "3200970", Drop: []string{"CVE-2016-7220"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3081320": {Override: []string{"3198510"}},
		},
	},
	"MS16-138": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3197873", Drop: []string{"CVE-2016-7225", "CVE-2016-7226"}},
			{KB: "3197874", Drop: []string{"CVE-2016-7225", "CVE-2016-7226"}},
			{KB: "3197876", Drop: []string{"CVE-2016-7225", "CVE-2016-7226"}},
			{KB: "3197877", Drop: []string{"CVE-2016-7225", "CVE-2016-7226"}},
		},
	},
	"MS16-141": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860", "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864", "CVE-2016-7865"}}}},
	"MS16-142": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-7196", "CVE-2016-7241"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-7241"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3185330": {Add: []string{"3197868"}},
			"3185331": {Add: []string{"3197874"}},
			"3185332": {Add: []string{"3197877"}},
		},
		IECumChain: map[string][]string{
			"3185319": {"3197655"},
		},
	},
	// MS16-144: no candidate in markdown — drop.
	"MS16-144": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2016-7281", "CVE-2016-7284", "CVE-2016-7287"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2016-7287"}},
			{Component: "Internet Explorer 11 on Windows 10", Drop: []string{"CVE-2016-7278", "CVE-2016-7284"}},
			{Remap: map[string]string{"CVE-2016-7293": ""}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3197655": {Add: []string{"3203621"}},
			"3197877": {Add: []string{"3205409"}},
		},
		IECumChain: map[string][]string{
			"3170106": {"3205400"},
			"3191492": {"3203621"},
			"3192391": {"3205394"},
			"3192393": {"3205408"},
			"3197867": {"3205394"},
			"3197873": {"3205400"},
			"3197874": {"3205401"},
			"3198585": {"3205383"},
			"3198586": {"3205386"},
			"3200970": {"3206632"},
		},
	},
	"MS16-146": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3204724", Drop: []string{"CVE-2016-7272", "CVE-2016-7273"}},
			{KB: "3205383", Drop: []string{"CVE-2016-7257"}},
			{KB: "3205386", Drop: []string{"CVE-2016-7257"}},
			{KB: "3205394", Drop: []string{"CVE-2016-7273"}},
			{KB: "3205400", Drop: []string{"CVE-2016-7257", "CVE-2016-7273"}},
			{KB: "3205401", Drop: []string{"CVE-2016-7257", "CVE-2016-7273"}},
			{KB: "3205408", Drop: []string{"CVE-2016-7257", "CVE-2016-7273"}},
			{KB: "3205409", Drop: []string{"CVE-2016-7257", "CVE-2016-7273"}},
			{KB: "3205638", Drop: []string{"CVE-2016-7257", "CVE-2016-7273"}},
			{KB: "3206632", Drop: []string{"CVE-2016-7257"}},
			{KB: "3207752", Drop: []string{"CVE-2016-7273"}},
		},
	},
	"MS16-148": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2016-7257", "CVE-2016-7262", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7268", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7298", "CVE-2016-7300"}},
			{KB: "2883033", Drop: []string{"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "2889841", Drop: []string{"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3114395", Drop: []string{"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3118380", Drop: []string{"CVE-2016-7274", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3127892", Drop: []string{"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3127968", Drop: []string{"CVE-2016-7274", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3127986", Drop: []string{"CVE-2016-7274", "CVE-2016-7276", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3127995", Drop: []string{"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3128008", Drop: []string{"CVE-2016-7264", "CVE-2016-7268"}},
			{KB: "3128016", Drop: []string{"CVE-2016-7264", "CVE-2016-7268"}},
			{KB: "3128019", Drop: []string{"CVE-2016-7267", "CVE-2016-7268"}},
			{KB: "3128020", Drop: []string{"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3128022", Drop: []string{"CVE-2016-7267", "CVE-2016-7268"}},
			{KB: "3128023", Drop: []string{"CVE-2016-7267", "CVE-2016-7268"}},
			{KB: "3128024", Drop: []string{"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"}},
			{KB: "3128025", Drop: []string{"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"}},
			{KB: "3128026", Drop: []string{"CVE-2016-7265"}},
			{KB: "3128029", Drop: []string{"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3128032", Drop: []string{"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"}},
			{KB: "3128034", Drop: []string{"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"}},
			{KB: "3128035", Drop: []string{"CVE-2016-7265"}},
			{KB: "3128037", Drop: []string{"CVE-2016-7264", "CVE-2016-7268"}},
			{KB: "3128043", Drop: []string{"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"}},
			{KB: "3128044", Drop: []string{"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267"}},
			{KB: "3198800", Drop: []string{"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7300"}},
			{KB: "3198808", Drop: []string{"CVE-2016-7266", "CVE-2016-7300"}},
			{KB: "3204068", Drop: []string{"CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7266", "CVE-2016-7268"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-7257", "CVE-2016-7274"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2016-7257", "CVE-2016-7274"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-7268"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2016-7268"}},
			{Component: "Microsoft Office 2016 (32-bit edition)", Drop: []string{"CVE-2016-7275", "CVE-2016-7277"}},
			{Component: "Microsoft Office 2016 (32-bit edition)", Drop: []string{"CVE-2016-7275", "CVE-2016-7277"}},
			{Component: "Microsoft Office 2016 (64-bit edition)", Drop: []string{"CVE-2016-7275", "CVE-2016-7277"}},
			{Component: "Microsoft Office 2016 (64-bit edition)", Drop: []string{"CVE-2016-7275", "CVE-2016-7277"}},
			{Component: "Microsoft Office for Mac 2011", Drop: []string{"CVE-2016-7290", "CVE-2016-7291"}},
			{Component: "Microsoft Office for Mac 2011", Drop: []string{"CVE-2016-7290", "CVE-2016-7291"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-7257", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7274", "CVE-2016-7276"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2016-7257", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7274", "CVE-2016-7276"}},
		},
	},
	"MS16-154": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870", "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874", "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878", "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890", "CVE-2016-7892"}}}},
	"MS16-155": {
		Supersedes: map[string]supersedesAdjust{
			"3163244": {Add: []string{"3210129"}},
			"3188744": {Add: []string{"3210129", "3210136", "3210139"}},
		},
	},
	"MS17-003": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2925", "CVE-2017-2926", "CVE-2017-2927", "CVE-2017-2928", "CVE-2017-2930", "CVE-2017-2931", "CVE-2017-2932", "CVE-2017-2933", "CVE-2017-2934", "CVE-2017-2935", "CVE-2017-2936", "CVE-2017-2937"}}}},
	"MS17-004": {
		Supersedes: map[string]supersedesAdjust{
			"3204808": {Add: []string{"3216775"}},
		},
	},
	"MS17-005": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2982", "CVE-2017-2984", "CVE-2017-2985", "CVE-2017-2986", "CVE-2017-2987", "CVE-2017-2988", "CVE-2017-2990", "CVE-2017-2991", "CVE-2017-2992", "CVE-2017-2993", "CVE-2017-2994", "CVE-2017-2995", "CVE-2017-2996"}}}},
	"MS17-006": {
		CVEAdjustments: []cveAdjustment{
			{Component: "Internet Explorer 9", Drop: []string{"CVE-2017-0012", "CVE-2017-0018", "CVE-2017-0033", "CVE-2017-0037", "CVE-2017-0049", "CVE-2017-0154"}},
			{Component: "Internet Explorer 10", Drop: []string{"CVE-2017-0012", "CVE-2017-0033", "CVE-2017-0049", "CVE-2017-0154"}},
			{Component: "Internet Explorer 11", Drop: []string{"CVE-2017-0154"}},
		},
	},
	"MS17-007": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-0009", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012", "CVE-2017-0015", "CVE-2017-0017", "CVE-2017-0023", "CVE-2017-0032", "CVE-2017-0033", "CVE-2017-0034", "CVE-2017-0035", "CVE-2017-0037", "CVE-2017-0065", "CVE-2017-0066", "CVE-2017-0067", "CVE-2017-0068", "CVE-2017-0069", "CVE-2017-0070", "CVE-2017-0071", "CVE-2017-0094", "CVE-2017-0131", "CVE-2017-0132", "CVE-2017-0133", "CVE-2017-0134", "CVE-2017-0135", "CVE-2017-0136", "CVE-2017-0137", "CVE-2017-0138", "CVE-2017-0140", "CVE-2017-0141", "CVE-2017-0150", "CVE-2017-0151"}}}},
	"MS17-008": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3211306", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0074", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012212", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0074", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012215", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0074", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0095", "CVE-2017-0098"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0021", "CVE-2017-0051"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0021", "CVE-2017-0051"}},
		},
	},
	"MS17-011": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0084", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0118", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0121", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
			{KB: "4013429", Drop: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}},
		},
	},
	// MS17-012: leading-zero typo of CVE-2017-0016 — remap (0016 not in
	// xlsx; the xlsx cell carries "CVE-2017-00016" with an extra zero).
	"MS17-012": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3217587", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0057", "CVE-2017-0100", "CVE-2017-0104"}},
			{KB: "4012021", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0039", "CVE-2017-0057", "CVE-2017-0100"}},
			{KB: "4012212", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0057"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0007", "CVE-2017-0039"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0039", "CVE-2017-0057"}},
			{KB: "4012215", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0057"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0007", "CVE-2017-0039"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0039", "CVE-2017-0057"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0039", "CVE-2017-0104"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0039", "CVE-2017-0104"}},
			{KB: "4013429", Drop: []string{"CVE-2017-0039"}},
			{Component: "Windows 10 Version 1607 for 32-bit Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 10 Version 1607 for 32-bit Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 10 Version 1607 for x64-based Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 10 Version 1607 for x64-based Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 7 for 32-bit Systems Service Pack 1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 8.1 for 32-bit Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows 8.1 for x64-based Systems", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows RT 8.1", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2017-0104"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", Drop: []string{"CVE-2017-0104"}},
			{Remap: map[string]string{"CVE-2017-00016": "CVE-2017-0016"}},
		},
	},
	"MS17-013": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3127945", Drop: []string{"CVE-2017-0014"}},
			{KB: "3127958", Drop: []string{"CVE-2017-0014"}},
			{KB: "3141535", Drop: []string{"CVE-2017-0014", "CVE-2017-0060", "CVE-2017-0073"}},
			{KB: "3178653", Drop: []string{"CVE-2017-0014", "CVE-2017-0060", "CVE-2017-0073"}},
			{KB: "3178688", Drop: []string{"CVE-2017-0060", "CVE-2017-0073"}},
			{KB: "3178693", Drop: []string{"CVE-2017-0014"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4012497", Drop: []string{"CVE-2017-0014", "CVE-2017-0038", "CVE-2017-0060", "CVE-2017-0061", "CVE-2017-0062", "CVE-2017-0063", "CVE-2017-0073", "CVE-2017-0108"}},
			{KB: "4012583", Drop: []string{"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0047", "CVE-2017-0061", "CVE-2017-0063"}},
			{KB: "4012584", Drop: []string{"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0038", "CVE-2017-0047", "CVE-2017-0060", "CVE-2017-0062", "CVE-2017-0073", "CVE-2017-0108"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4013429", Drop: []string{"CVE-2017-0061", "CVE-2017-0108"}},
			{KB: "4017018", Drop: []string{"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0047", "CVE-2017-0060", "CVE-2017-0061", "CVE-2017-0062", "CVE-2017-0063", "CVE-2017-0073", "CVE-2017-0108"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2008 for 32-bit Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2008 for Itanium-based Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2008 for x64-based Systems Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2017-0063"}},
			{Component: "Windows Server 2012 (Server Core installation)", Drop: []string{"CVE-2017-0063"}},
			{Component: "Windows Server 2016 for x64-based Systems", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Server 2016 for x64-based Systems", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Vista Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2017-0038"}},
			{Component: "Windows Vista x64 Edition Service Pack 2", Drop: []string{"CVE-2017-0038"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"2889841": {Add: []string{"3178688"}},
			"3115131": {Override: []string{"3178688"}},
		},
	},
	"MS17-014": {
		CVEAdjustments: []cveAdjustment{
			{KB: "3172431", Drop: []string{"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "3172457", Drop: []string{"CVE-2017-0006", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "3172464", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "3172542", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178673", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178674", Drop: []string{"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "3178676", Drop: []string{"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178677", Drop: []string{"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178678", Drop: []string{"CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0105"}},
			{KB: "3178680", Drop: []string{"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178682", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0052"}},
			{KB: "3178683", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0052"}},
			{KB: "3178684", Drop: []string{"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"}},
			{KB: "3178685", Drop: []string{"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "3178686", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"}},
			{KB: "3178687", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"}},
			{KB: "3178689", Drop: []string{"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"}},
			{KB: "3178690", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"}},
			{KB: "3178694", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"}},
			{KB: "4013241", Drop: []string{"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0052", "CVE-2017-0053"}},
			{Component: "Microsoft Excel 2016 for Mac", Drop: []string{"CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0105"}},
			{Component: "Microsoft Excel for Mac 2011", Drop: []string{"CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0105"}},
			{Component: "Microsoft Office 2016 for Mac", Drop: []string{"CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0105"}},
			{Component: "Microsoft Word for Mac 2011", Drop: []string{"CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0105"}},
		},
		Supersedes: map[string]supersedesAdjust{
			"3141542": {Add: []string{"3178687"}},
		},
	},
	"MS17-017": {
		CVEAdjustments: []cveAdjustment{
			{Add: []string{"CVE-2017-0050", "CVE-2017-0101", "CVE-2017-0102", "CVE-2017-0103"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0101", "CVE-2017-0103"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0101"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0101", "CVE-2017-0103"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0101"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0101", "CVE-2017-0103"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0101", "CVE-2017-0103"}},
			{KB: "4013429", Drop: []string{"CVE-2017-0101", "CVE-2017-0103"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
			{Component: "Windows 7 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
			{Component: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
			{Component: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", Drop: []string{"CVE-2017-0101"}},
		},
	},
	"MS17-018": {
		CVEAdjustments: []cveAdjustment{
			{KB: "4012212", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0078"}},
			{KB: "4012213", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0080", "CVE-2017-0082"}},
			{KB: "4012214", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0079", "CVE-2017-0080", "CVE-2017-0082"}},
			{KB: "4012215", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0078"}},
			{KB: "4012216", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0080", "CVE-2017-0082"}},
			{KB: "4012217", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0079", "CVE-2017-0080", "CVE-2017-0082"}},
			{KB: "4012497", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0078"}},
			{KB: "4012606", Drop: []string{"CVE-2017-0024"}},
			{KB: "4013198", Drop: []string{"CVE-2017-0024"}},
			{KB: "4013429", Drop: []string{"CVE-2017-0079", "CVE-2017-0082"}},
			{Component: "Windows Server 2016 for x64-based Systems", Drop: []string{"CVE-2017-0078"}},
			{Component: "Windows Server 2016 for x64-based Systems", Drop: []string{"CVE-2017-0078"}},
			{Component: "Windows Server 2016 for x64-based Systems (Server Core installation)", Drop: []string{"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0078"}},
		},
	},
	"MS17-023": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2997", "CVE-2017-2998", "CVE-2017-2999", "CVE-2017-3000", "CVE-2017-3001", "CVE-2017-3002", "CVE-2017-3003"}}}},
}

// lookupAmendment returns the amendment record for a row's bulletin, or
// the zero value if the bulletin has no amendments. Bulletin IDs are
// matched case-insensitively (markdown filenames and xlsx labels diverge
// in casing for some bulletins).
func lookupAmendment(bulletinID string) bulletinArchiveAmendment {
	return bulletinArchiveAmendments[strings.ToUpper(bulletinID)]
}

// applyCVEAdditions unions per-bulletin CVE tokens from each bulletin's
// bulletinArchiveAmendments record into each row's CVEs string. Used
// for bulletins where BulletinSearch.xlsx left the cves cell empty
// across every row despite the markdown documenting CVE attributions
// (or partially empty — only some xlsx rows carry CVEs). The record
// holds only curated CVE tokens; per-(KB, CVE) NA precision is enforced
// afterwards via KB-scoped Drop entries within the same amendments record.
//
// Idempotent: CVEs already present in row.CVEs are not duplicated. The
// comparison is case-insensitive to align with parseCVEs, which
// explicitly recognises the lowercase "cve-..." prefix as a historical
// xlsx anomaly and canonicalises it to uppercase downstream. Without
// the case fold here, an "applyCVEAdditions" pass against a row whose
// xlsx cell already contains "cve-XXXX-YYYY" would append a duplicate
// "CVE-XXXX-YYYY" entry — the row-level dedup loop later in extract()
// would still collapse them on output, but the intermediate string is
// avoided.
func applyCVEAdditions(rows []bulletin.Bulletin) []bulletin.Bulletin {
	// The Add adjustments are bulletin-scoped (empty KB and Component), so a
	// bulletin's additions are identical across all of its rows. Derive them
	// once per bulletin rather than rescanning CVEAdjustments for every row.
	additions := make(map[string][]string)
	for id, ad := range bulletinArchiveAmendments {
		var adds []string
		for _, adj := range ad.CVEAdjustments {
			if adj.KB == "" && adj.Component == "" && len(adj.Add) > 0 {
				adds = append(adds, adj.Add...)
			}
		}
		if len(adds) > 0 {
			additions[strings.ToUpper(id)] = adds
		}
	}

	for i, row := range rows {
		adds := additions[strings.ToUpper(row.BulletinID)]
		if len(adds) == 0 {
			continue
		}
		existing := make(map[string]struct{})
		for token := range strings.SplitSeq(row.CVEs, ",") {
			if t := strings.TrimSpace(token); t != "" {
				existing[strings.ToUpper(t)] = struct{}{}
			}
		}
		toAppend := make([]string, 0, len(adds))
		for _, cve := range adds {
			if _, ok := existing[strings.ToUpper(cve)]; ok {
				continue
			}
			toAppend = append(toAppend, cve)
		}
		if len(toAppend) == 0 {
			continue
		}
		if row.CVEs == "" {
			rows[i].CVEs = strings.Join(toAppend, ",")
		} else {
			rows[i].CVEs = row.CVEs + "," + strings.Join(toAppend, ",")
		}
	}
	return rows
}

// applyComponentReattributions returns a copy of rows expanded by each
// bulletin's bulletinArchiveAmendments.RowSplits. For each row whose
// (bulletin_id, component_kb) matches a split entry, the matching CVEs
// are removed from the original row's cves string and one synthesized
// row per split is appended carrying the listed affected_component and
// only the CVEs that were actually present on the source row.
//
// Three invariants guard against accidental data corruption:
//
//   - Only OS-only rows (affected_component empty) are eligible. Rows
//     that already carry an affected_component value are real
//     component rows and are passed through unchanged, even if their
//     (bulletin_id, component_kb) collides with a map entry — rewriting
//     them would silently corrupt Microsoft's own component attribution.
//   - CVE token comparison goes through parseCVEs so historical xlsx
//     format anomalies ("CVE-CVE-...", concatenated CVEs, whitespace,
//     case) are normalized the same way the main extract path does. A
//     row whose cves cell fails parseCVEs is passed through unchanged;
//     the main extract loop surfaces the parse error with full context.
//   - Only the intersection of (map entry's CVEs) ∩ (row's actual CVEs)
//     is moved. If a map entry lists a CVE that isn't on the source
//     row, that CVE is skipped (not synthesized). If none of an entry's
//     CVEs are present, the entire synth row is dropped. This makes
//     accidental map mistypes manifest as "no change" rather than as
//     silent over-attribution.
func applyComponentReattributions(rows []bulletin.Bulletin) []bulletin.Bulletin {
	out := make([]bulletin.Bulletin, 0, len(rows))
	for _, row := range rows {
		// Pass through rows that already carry a real affected_component
		// value — they are not the OS-only rows the map targets.
		if row.AffectedComponent != "" {
			out = append(out, row)
			continue
		}

		ad := lookupAmendment(row.BulletinID)
		var splits []rowSplit
		for _, s := range ad.RowSplits {
			if s.KB == row.ComponentKB {
				splits = append(splits, s)
			}
		}
		if len(splits) == 0 {
			out = append(out, row)
			continue
		}

		parsed, err := parseCVEs(row.CVEs)
		if err != nil {
			// Best-effort: defer the error to the main extract loop, which
			// will surface it with full context. Pass the row through
			// unchanged so we don't silently mutate a malformed row.
			out = append(out, row)
			continue
		}
		present := make(map[string]struct{}, len(parsed))
		for _, c := range parsed {
			present[c] = struct{}{}
		}

		// Build the synthesized rows from the intersection of each entry's
		// CVEs and the row's actual CVEs. Empty intersections are dropped.
		movedAll := make(map[string]struct{})
		synths := make([]rowSplit, 0, len(splits))
		for _, s := range splits {
			actual := make([]string, 0, len(s.CVEs))
			for _, c := range s.CVEs {
				if _, ok := present[c]; ok {
					actual = append(actual, c)
					movedAll[c] = struct{}{}
				}
			}
			if len(actual) == 0 {
				continue
			}
			synths = append(synths, rowSplit{KB: s.KB, Component: s.Component, CVEs: actual})
		}

		// Rebuild row.CVEs from the parsed list excluding moved CVEs. This
		// also re-canonicalises any anomalies parseCVEs handled, so the
		// downstream loop sees the normalized form.
		kept := make([]string, 0, len(parsed))
		for _, c := range parsed {
			if _, drop := movedAll[c]; drop {
				continue
			}
			kept = append(kept, c)
		}
		row.CVEs = strings.Join(kept, ",")
		out = append(out, row)

		for _, r := range synths {
			synth := row
			synth.AffectedComponent = r.Component
			synth.CVEs = strings.Join(r.CVEs, ",")
			out = append(out, synth)
		}
	}
	return out
}

func (e extractor) extract(rows []bulletin.Bulletin) ([]dataTypes.Data, []microsoftkbTypes.KB, error) {
	type dataGroup struct {
		advisories []advisoryTypes.Advisory
		vulns      []vulnerabilityTypes.Vulnerability
		conditions []conditionTypes.Condition
	}

	groups := make(map[dataTypes.RootID]dataGroup)
	kbProducts := make(map[string]map[string]struct{})
	kbSupersededBy := make(map[string]map[string]struct{}) // old KBID → set of new KBIDs

	for _, row := range applyComponentReattributions(applyCVEAdditions(rows)) {
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

		// Filter CVEs that the Bulletin archive markdown explicitly marks as
		// "Not applicable" for this row's (componentKB) or (bulletin, component)
		// pair, and apply per-bulletin xlsx CVE token corrections (remap typo
		// → canonical CVE, or drop when the canonical form is absent from the
		// markdown). BulletinSearch.xlsx groups every CVE of a bulletin row
		// in a single comma-separated cves cell, so a CVE that only applies
		// to a subset of OSes/IE versions in the bulletin gets attributed to
		// every row of that bulletin. The archive markdown's per-cell "Not
		// applicable" markers narrow this back to the authoritative per-(KB,
		// CVE) and per-(bulletin, component, CVE) attribution — drawn from
		// KB-scoped and Component-scoped Drop entries within the bulletin's
		// bulletinArchiveAmendments record. The amendments record also
		// carries per-bulletin Remap adjustments for xlsx CVE tokens that
		// are absent from the bulletin's markdown body (year-typos,
		// off-by-one suffixes, retracted CVEs, etc.).
		//
		// Most rows have no NA entry and no corrections, so look up all
		// inputs once per row and skip the per-CVE filter/remap loop
		// entirely when there is nothing to drop or remap. When the loop
		// does run, build sets for the NA lists and the dedup tracking so
		// each CVE costs O(1) instead of O(n) — some IE Cumulative rows
		// carry 30-50+ CVEs against equally large NA lists.
		componentKey := normalizeArchiveComponentKey(string(rootID), row.AffectedProduct, row.AffectedComponent)
		ad := lookupAmendment(string(rootID))
		var naCVEsKB []string
		var naCVEsComp []string
		var corrections map[string]string
		for _, adj := range ad.CVEAdjustments {
			if adj.KB != "" && adj.KB == row.ComponentKB && len(adj.Drop) > 0 {
				naCVEsKB = append(naCVEsKB, adj.Drop...)
			}
			if adj.Component != "" && adj.Component == componentKey && len(adj.Drop) > 0 {
				naCVEsComp = append(naCVEsComp, adj.Drop...)
			}
			if len(adj.Remap) > 0 {
				if corrections == nil {
					corrections = make(map[string]string, len(adj.Remap))
				}
				maps.Copy(corrections, adj.Remap)
			}
		}
		filteredIDs := ids
		if len(naCVEsKB) > 0 || len(naCVEsComp) > 0 || len(corrections) > 0 {
			naSet := make(map[string]struct{}, len(naCVEsKB)+len(naCVEsComp))
			for _, c := range naCVEsKB {
				naSet[c] = struct{}{}
			}
			for _, c := range naCVEsComp {
				naSet[c] = struct{}{}
			}
			seen := make(map[string]struct{}, len(ids))
			filteredIDs = make([]string, 0, len(ids))
			for _, cve := range ids {
				// Apply xlsx CVE token correction first (remap typo → canonical
				// CVE, or drop when fix is empty). The corrected token then
				// flows through the NA filters like any other CVE.
				if fix, ok := corrections[cve]; ok {
					if fix == "" {
						continue
					}
					cve = fix
				}
				if _, na := naSet[cve]; na {
					continue
				}
				if _, dup := seen[cve]; dup {
					continue
				}
				seen[cve] = struct{}{}
				filteredIDs = append(filteredIDs, cve)
			}
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
		for _, cve := range filteredIDs {
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
				KB:   &kbcTypes.Criterion{Product: microsoftutil.NormalizeProductName(pn), KBID: row.ComponentKB},
			}

			switch idx := slices.IndexFunc(g.conditions, func(c conditionTypes.Condition) bool {
				return c.Tag == segmentTypes.DetectionTag(pn)
			}); idx {
			case -1:
				g.conditions = append(g.conditions, conditionTypes.Condition{
					Criteria: criteriaTypes.Criteria{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterias: []criteriaTypes.Criteria{{
							Operator:   criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.Criterion{cn},
						}},
					},
					Tag: segmentTypes.DetectionTag(pn),
				})
			default:
				if len(g.conditions[idx].Criteria.Criterias) == 0 {
					g.conditions[idx].Criteria.Criterias = []criteriaTypes.Criteria{{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
					}}
				}
				if !slices.ContainsFunc(g.conditions[idx].Criteria.Criterias[0].Criterions, func(e criterionTypes.Criterion) bool {
					return e.KB != nil && e.KB.KBID == row.ComponentKB
				}) {
					g.conditions[idx].Criteria.Criterias[0].Criterions = append(g.conditions[idx].Criteria.Criterias[0].Criterions, cn)
				}
			}

			if _, ok := kbProducts[row.ComponentKB]; !ok {
				kbProducts[row.ComponentKB] = make(map[string]struct{})
			}
			kbProducts[row.ComponentKB][microsoftutil.NormalizeProductName(pn)] = struct{}{}

			for _, oldKBID := range parseSupersedes(row.Supersedes) {
				if _, ok := kbSupersededBy[oldKBID]; !ok {
					kbSupersededBy[oldKBID] = make(map[string]struct{})
				}
				kbSupersededBy[oldKBID][row.ComponentKB] = struct{}{}
			}
		}

		groups[rootID] = g
	}

	// A1: merge IE Cumulative in-track chain edges. Microsoft frequently stops
	// publishing month-to-month supersedes for IE 10/11 KBs starting Nov 2016
	// (MS16-142), leaving the chain incomplete. The Bulletin source is frozen
	// (retired April 2017), so each bulletin's IECumChain in
	// bulletinArchiveAmendments is a static snapshot of the chain edges that
	// bulletin contributed — see the type's doc comment for provenance.
	//
	// We iterate all bulletins' IECumChain maps (not kbProducts) so that entries
	// whose oldKBID is itself absent from BulletinSearch.xlsx (e.g., Monthly
	// Rollup KBs like 3197874/3198585/3198586/3200970) still contribute their
	// supersedes edge. The downstream loop below emits a KB record for any KBID
	// present only in kbSupersededBy, so those orphan oldKBs surface as
	// standalone KB entries carrying just their SupersededBy info, completing
	// the chain.
	for _, ad := range bulletinArchiveAmendments {
		for oldKBID, newKBIDs := range ad.IECumChain {
			if _, exists := kbSupersededBy[oldKBID]; !exists {
				kbSupersededBy[oldKBID] = make(map[string]struct{})
			}
			for _, newKBID := range newKBIDs {
				kbSupersededBy[oldKBID][newKBID] = struct{}{}
			}
		}
	}

	// Merge supersedes adjustments recovered from each bulletin's archive
	// markdown (https://learn.microsoft.com/en-us/security-updates/securitybulletins/...).
	// Each amendment's Supersedes[oldKB] carries:
	//   - Add: superseded-by KBs to union into kbSupersededBy[oldKB]
	//   - Override: superseded-by KBs that BulletinSearch.xlsx incorrectly
	//     attributes to oldKB and should be removed from kbSupersededBy[oldKB]
	//
	// Same iteration strategy as IECumChain above: iterate over all
	// bulletins' Supersedes maps so that archive-only oldKBs (Monthly Rollup
	// KBs not present as component_kbs in xlsx) still contribute their
	// supersedes edges. Adds are applied first across all bulletins, then
	// Overrides — preserves the legacy add-then-override ordering.
	for _, ad := range bulletinArchiveAmendments {
		for oldKBID, adj := range ad.Supersedes {
			if len(adj.Add) == 0 {
				continue
			}
			if _, exists := kbSupersededBy[oldKBID]; !exists {
				kbSupersededBy[oldKBID] = make(map[string]struct{})
			}
			for _, newKBID := range adj.Add {
				kbSupersededBy[oldKBID][newKBID] = struct{}{}
			}
		}
	}
	for _, ad := range bulletinArchiveAmendments {
		for oldKBID, adj := range ad.Supersedes {
			for _, newKBID := range adj.Override {
				news, ok := kbSupersededBy[oldKBID]
				if !ok {
					continue
				}
				delete(news, newKBID)
				if len(news) == 0 {
					delete(kbSupersededBy, oldKBID)
				}
			}
		}
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

	// MicrosoftKB entries
	kbs := make([]microsoftkbTypes.KB, 0, len(kbProducts)+len(kbSupersededBy))
	for kbID, products := range kbProducts {
		kb := microsoftkbTypes.KB{
			KBID:     kbID,
			URL:      fmt.Sprintf("https://support.microsoft.com/help/%s", kbID),
			Products: slices.Collect(maps.Keys(products)),
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftBulletin,
				Raws: e.r.Paths(),
			},
		}
		if newKBIDs, ok := kbSupersededBy[kbID]; ok {
			for newKBID := range newKBIDs {
				kb.SupersededBy = append(kb.SupersededBy, microsoftkbSupersededByTypes.SupersededBy{KBID: newKBID})
			}
			delete(kbSupersededBy, kbID)
		}
		kbs = append(kbs, kb)
	}
	for oldKBID, newKBIDs := range kbSupersededBy {
		ss := make([]microsoftkbSupersededByTypes.SupersededBy, 0, len(newKBIDs))
		for newKBID := range newKBIDs {
			ss = append(ss, microsoftkbSupersededByTypes.SupersededBy{KBID: newKBID})
		}
		kbs = append(kbs, microsoftkbTypes.KB{
			KBID:         oldKBID,
			URL:          fmt.Sprintf("https://support.microsoft.com/help/%s", oldKBID),
			SupersededBy: ss,
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftBulletin,
				Raws: e.r.Paths(),
			},
		})
	}
	microsoftutil.DeriveSupersedes(kbs)

	return datas, kbs, nil
}
