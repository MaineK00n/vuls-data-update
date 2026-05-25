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
	// KB3116869 / CVE-2015-6108) is recovered by bulletinArchiveComponentReattribution
	// — see that map's doc comment.
	case "MS12-054", "MS12-074",
		"MS13-046", "MS13-081",
		"MS15-097", "MS15-128",
		"MS16-014", "MS16-015", "MS16-045", "MS16-062", "MS16-067", "MS16-088",
		"MS16-090", "MS16-097", "MS16-099", "MS16-106", "MS16-107", "MS16-108", "MS16-111",
		"MS16-133", "MS16-135", "MS16-148",
		"MS17-012", "MS17-013", "MS17-017", "MS17-018":
		return product
	default:
		// MS14-* through MS16-* IE Cumulative layout: IE identity in
		// affected_component, OS in affected_product.
		if key := ieEdgeComponentKey(component, product); key != "" {
			return key
		}
		return ""
	}
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

// componentReattribution describes a synthetic per-component row that should be
// emitted alongside an OS-only xlsx row. See bulletinArchiveComponentReattribution.
type componentReattribution struct {
	Component string   // affected_component value to set on the synthesized row
	CVEs      []string // CVEs to move from the OS row to the synthesized row
}

// bulletinArchiveComponentReattribution captures per-component CVE attributions that
// Microsoft documents in component matrix tables but BulletinSearch.xlsx
// collapses into the OS-only row (because Microsoft did not emit a
// distinct xlsx row for the OS + component configuration). At extract
// time, the listed CVEs are moved from the OS row's cves to a
// synthesized row carrying the listed affected_component, preserving
// the markdown's per-configuration precision and producing a separate
// detection segment for the (OS + component) configuration.
//
// Map shape: bulletinID → component_kb → []componentReattribution
//
// Each entry encodes a specific markdown row from a component matrix
// table whose configuration is reachable in production (i.e. customers
// could have that OS + component combination installed) but absent
// from xlsx as a standalone row. Without the split, a scanner would
// either flag the OS row for CVEs it isn't actually exposed to (FP) or
// silently miss the configuration entirely.
//
// Example: MS15-128 / KB3116869 — the bulletin's .NET Framework 3.5
// component matrix table marks Win 10 / KB3116869 as Critical RCE for
// CVE-2015-6108, but xlsx only carries the OS-only Win 10 row
// (cves=CVE-2015-6106,CVE-2015-6107,CVE-2015-6108, affected_component
// absent). Splitting the .NET 3.5 attribution off produces two
// detection rows: the OS-only row covering CVE-2015-6107, and a
// synthesized "Windows 10 + .NET Framework 3.5" row covering
// CVE-2015-6108 (CVE-2015-6106 is dropped earlier by
// bulletinArchiveKBNotApplicable as truly NA for Win 10).
//
// MS15-128 / KB3116869 / CVE-2015-6108 is the ONLY such case in the
// MSRC bulletin archive corpus. A corpus-wide audit (per-(KB, CVE)
// cross-table cell scan + xlsx component-row presence check) surfaced
// no other bulletins where (a) the markdown documents a component
// configuration with a CVE that the OS-only context marks NA AND (b)
// xlsx is missing the (OS + component, KB) row. Additional candidates
// the audit surfaced (e.g. MS08-040, MS09-004, MS09-024, MS09-062,
// MS12-027) turned out to share applicability between OS-only and
// OS+component contexts, so the xlsx OS row already attributes the
// CVEs correctly — no reattribution needed. The map is therefore
// expected to stay at one entry unless Microsoft re-publishes the
// archive in a structurally different way.
var bulletinArchiveComponentReattribution = map[string]map[string][]componentReattribution{
	"MS15-128": {
		"3116869": {
			{Component: "Microsoft .NET Framework 3.5", CVEs: []string{"CVE-2015-6108"}},
		},
	},
}

// applyCVEAdditions unions per-bulletin CVE tokens from
// bulletinArchiveCVEAdditions into each row's CVEs string. Used for
// bulletins where BulletinSearch.xlsx left the cves cell empty across
// every row despite the markdown documenting CVE attributions; see the
// map's doc comment for the rationale and ordering vs. per-(KB, CVE) NA
// filtering.
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
	for i, row := range rows {
		adds := bulletinArchiveCVEAdditions[strings.ToUpper(row.BulletinID)]
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

// applyComponentReattributions returns a copy of rows expanded by
// bulletinArchiveComponentReattribution. For each row whose
// (bulletin_id, component_kb) matches an entry, the matching CVEs are
// removed from the original row's cves string and one synthesized row
// per reattribution entry is appended carrying the listed
// affected_component and only the CVEs that were actually present on
// the source row.
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

		reattributions, ok := bulletinArchiveComponentReattribution[strings.ToUpper(row.BulletinID)][row.ComponentKB]
		if !ok {
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
		synths := make([]componentReattribution, 0, len(reattributions))
		for _, r := range reattributions {
			actual := make([]string, 0, len(r.CVEs))
			for _, c := range r.CVEs {
				if _, ok := present[c]; ok {
					actual = append(actual, c)
					movedAll[c] = struct{}{}
				}
			}
			if len(actual) == 0 {
				continue
			}
			synths = append(synths, componentReattribution{Component: r.Component, CVEs: actual})
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
		// CVE) and per-(bulletin, component, CVE) attribution — see the two
		// static maps bulletinArchiveKBNotApplicable (KB-keyed, from
		// OS/Software-rows × CVE-cols tables) and
		// bulletinArchiveComponentNotApplicable ((bulletin, component)-keyed,
		// from CVE-rows × IE-version-cols severity tables) below.
		// bulletinArchiveCVECorrections handles xlsx tokens that are absent
		// from the bulletin's markdown body (year-typos, off-by-one suffixes,
		// retracted CVEs, etc.).
		//
		// Most rows have no NA entry and no corrections, so look up all three
		// inputs once per row and skip the per-CVE filter/remap loop entirely
		// when there is nothing to drop or remap. When the loop does run,
		// build sets for the NA lists and the dedup tracking so each CVE
		// costs O(1) instead of O(n) — some IE Cumulative rows carry 30-50+
		// CVEs against equally large NA lists.
		naCVEsKB := bulletinArchiveKBNotApplicable[row.ComponentKB]
		naCVEsComp := bulletinArchiveComponentNotApplicable[string(rootID)][normalizeArchiveComponentKey(string(rootID), row.AffectedProduct, row.AffectedComponent)]
		corrections := bulletinArchiveCVECorrections[string(rootID)]
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
	// (retired April 2017), so ieCumChainEdges is a static snapshot of the chain
	// — see its doc comment for provenance.
	//
	// We iterate the map's keys (not kbProducts) so that entries whose oldKBID
	// is itself absent from BulletinSearch.xlsx (e.g., Monthly Rollup KBs like
	// 3197874/3198585/3198586/3200970) still contribute their supersedes edge.
	// The downstream loop below emits a KB record for any KBID present only in
	// kbSupersededBy, so those orphan oldKBs surface as standalone KB entries
	// carrying just their SupersededBy info, completing the chain.
	for oldKBID, newKBIDs := range ieCumChainEdges {
		if _, exists := kbSupersededBy[oldKBID]; !exists {
			kbSupersededBy[oldKBID] = make(map[string]struct{})
		}
		for _, newKBID := range newKBIDs {
			kbSupersededBy[oldKBID][newKBID] = struct{}{}
		}
	}

	// Merge supersedes edges recovered from the Bulletin archive markdown
	// (https://learn.microsoft.com/en-us/security-updates/securitybulletins/...)
	// where BulletinSearch.xlsx omits them. See bulletinArchiveSupersedes for
	// provenance. Same iteration strategy as ieCumChainEdges above: iterate the
	// map's keys so that archive-only oldKBs (Monthly Rollup KBs not present as
	// component_kbs in xlsx) still contribute their supersedes edges.
	for oldKBID, newKBIDs := range bulletinArchiveSupersedes {
		if _, exists := kbSupersededBy[oldKBID]; !exists {
			kbSupersededBy[oldKBID] = make(map[string]struct{})
		}
		for _, newKBID := range newKBIDs {
			kbSupersededBy[oldKBID][newKBID] = struct{}{}
		}
	}

	// Drop supersedes edges that BulletinSearch.xlsx attributes to the wrong
	// component_kb (typically Excel cites the supersedes of a sibling component
	// release in the same bulletin). See bulletinArchiveSupersedesOverride for
	// provenance. Same iteration strategy as the merge loops above: iterate the
	// map's keys so that no override entry is silently dropped if its newKBID
	// happens to be absent from kbProducts.
	for newKBID, oldKBIDs := range bulletinArchiveSupersedesOverride {
		for _, oldKBID := range oldKBIDs {
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

// ieCumChainEdges synthesizes month-to-month SupersededBy edges between
// Internet Explorer Cumulative bulletins for the same (product, component)
// group. Microsoft frequently stops publishing the explicit month-to-month
// edge starting with MS16-142 (Nov 2016) for IE 10/11, leaving in-track
// chains incomplete.
//
// The Bulletin source is frozen (retired April 2017), so this map is a static
// exhaustive snapshot. It was generated by scanning bulletin rows whose title
// matches `(?i)^(cumulative\s+)?security\s+update\s+for\s+internet\s+explorer$`,
// grouping by (NormalizeProductName(productName(affected_product, affected_component)),
// affected_component), sorting each group by date_posted, and emitting
// consecutive-month (oldKBID → newKBID) edges. Edges already published in the
// raw data are merged downstream, so overlaps here are harmless.
var ieCumChainEdges = map[string][]string{
	"832894":  {"867801"},
	"834707":  {"889293", "890923"},
	"867801":  {"834707", "890923", "896727"},
	"883939":  {"896727", "931768", "944533"},
	"889293":  {"883939", "890923"},
	"890923":  {"883939", "896727", "944533"},
	"896688":  {"905915"},
	"896727":  {"896688"},
	"905915":  {"910620", "912812"},
	"910620":  {"912812"},
	"912812":  {"916281"},
	"916281":  {"918899"},
	"918899":  {"922760"},
	"922760":  {"928090"},
	"928090":  {"931768"},
	"931768":  {"933566"},
	"933566":  {"937143"},
	"937143":  {"939653"},
	"939653":  {"942615"},
	"942615":  {"944533", "947864"},
	"944533":  {"947864"},
	"947864":  {"950759"},
	"950759":  {"953838"},
	"953838":  {"956390"},
	"956390":  {"958215"},
	"958215":  {"960714"},
	"960714":  {"963027"},
	"963027":  {"969897"},
	"969897":  {"972260"},
	"972260":  {"974455"},
	"974455":  {"976325"},
	"976325":  {"978207"},
	"978207":  {"980182"},
	"980182":  {"982381"},
	"982381":  {"2183461"},
	"2183461": {"2360131"},
	"2360131": {"2416400"},
	"2416400": {"2482017"},
	"2482017": {"2497640"},
	"2497640": {"2530548"},
	"2530548": {"2559049"},
	"2559049": {"2586448"},
	"2586448": {"2618444"},
	"2618444": {"2647516"},
	"2647516": {"2675157"},
	"2675157": {"2699988"},
	"2699988": {"2719177", "2722913"},
	"2719177": {"2722913"},
	"2722913": {"2744842"},
	"2744842": {"2761451", "2761465"},
	"2761451": {"2761465"},
	"2761465": {"2792100", "2799329"},
	"2792100": {"2809289"},
	"2799329": {"2792100"},
	"2809289": {"2817183"},
	"2817183": {"2829530"},
	"2829530": {"2838727", "2847204"},
	"2838727": {"2846071"},
	"2846071": {"2862772"},
	"2847204": {"2838727"},
	"2862772": {"2870699"},
	"2870699": {"2879017"},
	"2879017": {"2888505"},
	"2884101": {"2888505"},
	"2888505": {"2898785"},
	"2898785": {"2909921"},
	"2909921": {"2925418"},
	"2925418": {"2936068", "2964358"},
	"2936068": {"2964358"},
	"2953522": {"2957689", "2961851"},
	"2956058": {"2956073"},
	"2956097": {"2956098"},
	"2957689": {"2962872", "2963950"},
	"2961851": {"2957689"},
	"2962872": {"2963952", "2976627"},
	"2963950": {"2962872"},
	"2963952": {"2976627"},
	"2964358": {"2953522", "2964444"},
	"2964444": {"2953522"},
	"2976627": {"2977629", "2987107"},
	"2977629": {"2987107"},
	"2987107": {"3003057"},
	"3003057": {"3008923"},
	"3008923": {"3021952"},
	"3021952": {"3032359", "3034196"},
	"3032359": {"3038314"},
	"3034196": {"3032359"},
	"3038314": {"3049563"},
	"3049563": {"3058515"},
	"3058515": {"3065822"},
	"3065822": {"3078071"},
	"3078071": {"3087985"},
	"3081444": {"3097617"},
	"3087038": {"3093983"},
	"3087985": {"3087038"},
	"3093983": {"3100773"},
	"3097617": {"3105213"},
	"3100773": {"3104002"},
	"3104002": {"3124275"},
	"3105211": {"3116900"},
	"3105213": {"3116869"},
	"3116869": {"3124266"},
	"3116900": {"3124263"},
	"3124263": {"3135173"},
	"3124266": {"3135174"},
	"3124275": {"3134814"},
	"3134814": {"3139929"},
	"3135173": {"3140768"},
	"3135174": {"3140745"},
	"3139929": {"3148198"},
	"3140745": {"3147461"},
	"3140768": {"3147458"},
	"3147458": {"3156421"},
	"3147461": {"3156387"},
	"3148198": {"3154070"},
	"3154070": {"3160005"},
	"3156387": {"3163017"},
	"3156421": {"3163018"},
	"3160005": {"3170106"},
	"3163912": {"3176492"},
	"3170106": {"3175443", "3191492", "3192391", "3192393", "3205400"},
	"3172985": {"3176493"},
	"3175443": {"3185319"},
	"3176492": {"3185611"},
	"3176493": {"3185614"},
	"3176495": {"3189866"},
	"3185319": {"3185331", "3192391", "3192392", "3197655", "3197867", "3197876"},
	"3185331": {"3197874"},
	"3185611": {"3192440"},
	"3185614": {"3192441"},
	"3189866": {"3194798"},
	"3191492": {"3203621"},
	"3192391": {"3197867", "3205394"},
	"3192392": {"3197873"},
	"3192393": {"3205408"},
	"3192440": {"3198585"},
	"3192441": {"3198586"},
	"3194798": {"3200970"},
	"3197867": {"3205394"},
	"3197873": {"3205400"},
	"3197874": {"3205401"},
	"3198585": {"3205383"},
	"3198586": {"3205386"},
	"3200970": {"3206632"},
}

// bulletinArchiveSupersedes captures supersedes edges that are missing from the
// BulletinSearch.xlsx Supersedes column but present in the corresponding
// Bulletin archive page on Microsoft Learn. Keys are old KBIDs that the Excel
// row for the newer KB fails to list as superseded; values are the newer KBIDs
// that the archive identifies as their replacement.
//
// The Bulletin source is frozen (retired April 2017), so this map is a static
// snapshot. It was generated by parsing the "Updates Replaced" column of the
// Affected Software table in each archive markdown and diffing against the
// Excel-derived per-(bulletin_id, component_kb) supersedes set. Only safe
// additions are included:
//   - Cases where the archive's set is a strict superset of the Excel's set
//     for the same (bulletin_id, component_kb); the extras are added here.
//   - Cases where a component_kb appears in the archive but not the Excel;
//     the archive's full set is added here.
//
// Cases where Excel attributes the supersedes to a different component_kb than
// the archive (Excel mis-attribution) are intentionally not handled by this
// additive map and are corrected elsewhere.
//
// Each entry's trailing comment identifies the source bulletin and product
// context for verification. The bulletin ID is the bulletin whose archive page
// publishes the newer KB and lists the old KB under "Updates Replaced". The
// archive page lives at:
//
//	https://learn.microsoft.com/en-us/security-updates/securitybulletins/<YYYY>/<bulletin-id-lowercase>
//
// Entries tagged "archive-only" have a newer KB that does not appear as a
// component_kb anywhere in BulletinSearch.xlsx but is present in the markdown
// archive — typically because the Excel either misses the bulletin's re-release
// rows (e.g., MS15-046 V4.0 adds KB3085544) or only enumerates the bulletin's
// "Security Only Release" rows while the markdown archive also lists the
// "Monthly Rollup Release" component package KBs (e.g., MS16-155 lists 3210129
// under parent KB3210142). The trailing note attributes the bulletin from the
// archive markdown where the supersedes edge appears (e.g., MS16-155).
//
// Ordering convention: entries are sorted by (bulletin year, bulletin number,
// KBID) — the primary bulletin is taken from the first MS<YY>-<NNN> token in
// the trailing comment so reviewers can scan the archive pages in chronology.
// New entries must follow this convention.
var bulletinArchiveSupersedes = map[string][]string{
	"2797052": {"2809289"},                       // MS13-021: IE 6 Cumulative (XP SP3)
	"2620712": {"2813170"},                       // MS13-031: Windows Kernel EoP (XP SP3)
	"2621146": {"2772930"},                       // MS13-032: Active Directory DoS (Server 2003 SP2)
	"2646524": {"2820917"},                       // MS13-033: CSRSS EoP (XP SP3)
	"2813170": {"2829361"},                       // MS13-046: Kernel-Mode Drivers EoP (XP SP3)
	"2847204": {"2838727"},                       // MS13-047: IE 6 Cumulative (XP SP3)
	"2829361": {"2839229"},                       // MS13-048: Windows Kernel info disclosure (XP SP3)
	"2698035": {"2833951"},                       // MS13-052: .NET FW 1.0 SP3 (XP MCE 2005 SP3)
	"2808735": {"2850851"},                       // MS13-053: Kernel-Mode Drivers RCE (XP SP3)
	"2827751": {"2843162"},                       // MS13-054: Lync 2010 Attendee user-install (GDI+); Excel mis-attributed to admin-install KB
	"2827752": {"2843163"},                       // MS13-054: Lync 2010 Attendee admin-install (GDI+)
	"981322":  {"2850869"},                       // MS13-060: Unicode Scripts Processor RCE (XP SP3 / Server 2003)
	"2746164": {"2874216"},                       // MS13-061: Exchange Server 2010 SP2 RCE
	"970238":  {"2849470"},                       // MS13-062: RPC EoP (XP SP3)
	"2360937": {"2849470"},                       // MS13-062: RPC EoP (XP SP3)
	"2644615": {"2859537"},                       // MS13-063: Windows Kernel EoP (XP SP3)
	"2790113": {"2859537"},                       // MS13-063: Windows Kernel EoP (Win7)
	"2859537": {"2872339", "3033395"},            // 2872339=MS13-077 (SCM EoP, Win7 SP1); 3033395=MS15-025 (Kernel EoP, Server 2003 SP2)
	"2866475": {"2880833"},                       // MS13-105: Exchange Server 2013 RCE
	"2837615": {"2878236"},                       // MS14-017: Office Compatibility Pack SP3 (Word RCE)
	"2863867": {"2878304"},                       // MS14-017: Office Word Viewer RCE
	"2889496": {"2939132"},                       // MS14-017: Office for Mac 2011 (Word RCE)
	"2936068": {"2953522", "2961851"},            // MS14-029: IE 8 / IE 11 (Win7 SP1) — IE update bundle
	"2964444": {"2953522"},                       // MS14-029: IE 8 Cumulative (Win7 SP1)
	"2961851": {"2957689"},                       // MS14-035: IE 11 Cumulative (Server 2008 R2 SP1)
	"2957689": {"2962872", "2963952"},            // MS14-037: IE 8 (Vista SP2) / IE 11 (Win7 SP1) — IE Cum chain
	"2716435": {"2977322"},                       // MS14-044: SQL Server 2008 SP3 EoP (QFE branch)
	"2844286": {"2937610"},                       // MS14-046: .NET FW 3.5.1 sec-feature-bypass (Win7 SP1)
	"2844287": {"2937608"},                       // MS14-046: .NET FW 2.0 SP2 sec-feature-bypass (Vista SP2)
	"2844289": {"2966825"},                       // MS14-046: .NET FW 3.5 sec-feature-bypass (Server 2012)
	"2898866": {"2966825"},                       // MS14-046: .NET FW 3.5 sec-feature-bypass (Server 2012)
	"2898868": {"2966826"},                       // MS14-046: .NET FW 3.5 sec-feature-bypass (Win8.1)
	"2962872": {"2976627", "2977629"},            // 2976627=MS14-051 (IE 8, Win7 SP1); 2977629=MS14-052 (IE 11, Server 2008 R2 SP1)
	"2756918": {"2973115"},                       // MS14-053: .NET FW 3.0 SP2 DoS (Server 2003 SP2)
	"2729460": {"2972107"},                       // MS14-057: .NET FW 4.5/4.5.1/4.5.2 RCE (Server 2008 R2 SP1)
	"3029449": {"3021952"},                       // MS15-009: IE 10 Cumulative (Win8/Server 2012/Win RT)
	"2536276": {"3000483"},                       // MS15-011: Group Policy RCE (Vista/Server 2008/Win7/Server 2008 R2)
	"2827328": {"2920791"},                       // MS15-012: Excel Viewer 2007 SP2 RCE
	"3012176": {"3032359"},                       // MS15-018: IE 8 Cumulative (Server 2003/Vista/Server 2008/Win7/Server 2008 R2)
	"3034196": {"3032359"},                       // MS15-018: IE 9/10/11 Cumulative (Vista/Server 2008/Win7/Server 2008 R2/Win8/Server 2012)
	"3036197": {"3032359"},                       // MS15-018: IE 11 Cumulative (Win8.1/Server 2012 R2/Win RT 8.1)
	"2962123": {"3039066"},                       // MS15-020: Windows Shell RCE (Win8.1/Server 2012 R2/Win RT 8.1)
	"2829254": {"3042553"},                       // MS15-034: HTTP.sys RCE (Win8/Server 2012)
	"2876331": {"3046306"},                       // MS15-035: Graphics Component RCE (Server 2003/Vista/Server 2008/Win7/Server 2008 R2)
	"2974286": {"3046002"},                       // MS15-045: Windows Journal RCE (Win8.1/Server 2012 R2)
	"2826028": {"3054838"},                       // MS15-046: Excel Web App 2010 SP2 (Office Web Apps 2010 SP2)
	"2826029": {"3054839"},                       // MS15-046: Excel Services (SharePoint 2010 SP2)
	"2956070": {"3054843"},                       // MS15-046: Office Web Apps 2010 SP2
	"2956136": {"3054833"},                       // MS15-046: Word Automation Services (SharePoint 2010 SP2)
	"2956208": {"3054847"},                       // MS15-046: SharePoint Foundation 2010 SP2
	"3051737": {"3048688"},                       // MS15-046: Office for Mac 2011
	"3054888": {"3085544"},                       // MS15-046: Office 2007 SP3 (V4.0 Oct 2015 re-release of 2965282) — archive-only
	"2804577": {"3035488"},                       // MS15-048: .NET FW 2.0 SP2 EoP (Server 2003 SP2)
	"2863239": {"3035488"},                       // MS15-048: .NET FW 2.0 SP2 EoP (Server 2003 SP2)
	"3050514": {"3061518"},                       // MS15-055: Schannel info disclosure (Win8/Server 2012)
	"3003381": {"3062577"},                       // MS15-062: AD FS 2.0 EoP (Server 2008 SP2)
	"2965155": {"3069392"},                       // MS15-072: Graphics Component EoP (Win8.1/Server 2012 R2)
	"3081444": {"3081455"},                       // MS15-095: Microsoft Edge Cumulative (Win10) — MS15-097/098/101/102/105 also republished
	"3062157": {"3087126"},                       // MS15-103: Exchange Server 2013 CU8 info disclosure
	"2901128": {"3098779"},                       // MS15-118: .NET FW 4.5.1/4.5.2 EoP (Win8.1)
	"2973408": {"3092601"},                       // MS15-119: Winsock EoP (Win8.1/Server 2012 R2)
	"3124001": {"3134214"},                       // MS16-018: Kernel-Mode Drivers EoP (Server 2012)
	"3138327": {"3142577"},                       // MS16-042: Word 2016 for Mac — archive-only
	"3138328": {"3154208"},                       // MS16-042: Word for Mac 2011 — archive-only
	"3148198": {"3154070"},                       // MS16-051: IE 9 Cumulative (Vista SP2)
	"2760585": {"2984943"},                       // MS16-054: Office 2007 SP3 (Office re-release)
	"2760591": {"2984938"},                       // MS16-054: Office 2007 SP3 (Office re-release)
	"3054841": {"3101520"},                       // MS16-054: Office 2010 SP2 (32-bit)
	"3054848": {"3054984"},                       // MS16-054: Office 2010 SP2 (32-bit)
	"3114486": {"3115016"},                       // MS16-054: Office 2013 SP1 (32-bit)
	"3114855": {"3115094"},                       // MS16-054: Word 2016 (32-bit)
	"3114982": {"3115115"},                       // MS16-054: Office Compatibility Pack SP3
	"3114983": {"3115116"},                       // MS16-054: Word 2007 SP3
	"3114987": {"3115132"},                       // MS16-054: Office Word Viewer
	"3114990": {"3115121"},                       // MS16-054: Office 2010 SP2 (32-bit)
	"3114993": {"3115123"},                       // MS16-054: Word 2010 SP2 (32-bit)
	"3115309": {"3115464"},                       // MS16-054 V2.0 (Aug 2016): Office Compatibility Pack SP3 — archive-only
	"3142577": {"3155777"},                       // MS16-054: Word 2016 for Mac
	"3154208": {"3155776"},                       // MS16-054: Word for Mac 2011
	"982666":  {"3141083"},                       // MS16-058: IIS (Server 2008 Itanium SP2)
	"3114421": {"3114740"},                       // MS16-070: Visio 2007 SP3
	"3114527": {"3115144"},                       // MS16-070: Office 2016 (64-bit)
	"3114892": {"3115107"},                       // MS16-070: Excel 2007 SP3
	"3114895": {"3115111"},                       // MS16-070: Office Compatibility Pack SP3
	"3114927": {"3115014"},                       // MS16-070: Word Automation Services (SharePoint 2013 SP1)
	"3114934": {"3115170"},                       // MS16-070: Office Web Apps Server 2013 SP1
	"3115115": {"3115194"},                       // MS16-070: Office Compatibility Pack SP3
	"3115116": {"3115195"},                       // MS16-070: Word 2007 SP3
	"3115117": {"3115196"},                       // MS16-070: Word Automation Services (SharePoint 2010 SP2)
	"3115124": {"3115244"},                       // MS16-070: Office Web Apps 2010 SP2
	"3115132": {"3115187"},                       // MS16-070: Office Word Viewer
	"3114742": {"3114893"},                       // MS16-099: Office 2007 SP3
	"3115311": {"3115465"},                       // MS16-099: Word 2007 SP3
	"3115393": {"3115480"},                       // MS16-099: Office Word Viewer
	"3115395": {"3115479"},                       // MS16-099: Office Word Viewer
	"3175024": {"3185330"},                       // MS16-101: Windows Authentication (Server 2008 R2 SP1)
	"3157569": {"3175887"},                       // MS16-102: Windows PDF Library (Win8.1)
	"3115254": {"3115487"},                       // MS16-107: PowerPoint 2013 SP1 (32-bit)
	"3185319": {"3185330", "3185331", "3185332"}, // MS16-118: IE Cumulative (Win7/8.1/Server 2008 R2/2012/2012 R2/Win RT) — Monthly Rollup KBs supersede 3185319 in MS16-104; archive-only (Monthly Rollup KBs)
	"3142041": {"3188735"},                       // MS16-120: .NET FW 3.0 SP2 (Vista SP2) — Graphics Component
	"3142042": {"3188740"},                       // MS16-120: .NET FW 3.5.1 (Win7 SP1) — Graphics Component
	"3142043": {"3188741"},                       // MS16-120: .NET FW 3.5 (Server 2012) — Graphics Component
	"3142045": {"3188743"},                       // MS16-120: .NET FW 3.5 (Win8.1) — Graphics Component
	"3115443": {"3118352"},                       // MS16-121: Word Automation Services (SharePoint 2013 SP1) — archive-only
	"3115466": {"3118377"},                       // MS16-121: Word Automation Services (SharePoint 2010 SP2) — archive-only
	"3115472": {"3118384"},                       // MS16-121: Office Web Apps 2010 SP2 — archive-only
	"3118270": {"3118360"},                       // MS16-121: Office Web Apps Server 2013 SP1 — archive-only
	"3118299": {"3127897"},                       // MS16-121: Office Online Server — archive-only
	"3184122": {"3194371"},                       // MS16-135: Kernel-Mode Drivers (Vista SP2)
	"3185330": {"3197868"},                       // MS16-142: IE 11 Monthly Rollup (Win7 SP1 / Server 2008 R2 SP1) — archive-only (Excel has Security Only KBs)
	"3185331": {"3197874"},                       // MS16-142: IE 11 Monthly Rollup (Win8.1 / Server 2012 R2 / Win RT 8.1) — archive-only
	"3185332": {"3197877"},                       // MS16-142: IE 10 Monthly Rollup (Server 2012) — archive-only
	"3197655": {"3203621"},                       // MS16-144: IE 9 Cumulative (Vista SP2)
	"3197877": {"3205409"},                       // MS16-144: IE 10 Monthly Rollup (Server 2012) — archive-only
	"3163244": {"3210129"},                       // MS16-155: .NET FW 2.0 SP2 (Vista/Server 2008 SP2) — Monthly Rollup component of parent KB3210142, archive-only
	"3188744": {"3210129", "3210136", "3210139"}, // MS16-155: .NET FW 2.0 SP2 / 4.5.2 / 4.6 (Vista/Server 2008 SP2) — Monthly Rollup components of parent KB3210142, archive-only
	"3204808": {"3216775"},                       // MS17-004: LSASS DoS (Server 2008 SP2)
	"2889841": {"3178688"},                       // MS17-013: Office 2010 SP2 (Graphics Component)
	"3141542": {"3178687"},                       // MS17-014: Word 2010 SP2 (32-bit)
}

// bulletinArchiveSupersedesOverride drops supersedes edges that
// BulletinSearch.xlsx attributes to the wrong component_kb. Keys are component
// KBIDs (the newer KB) emitted by this extractor; values are the old KBIDs
// that Excel claims the new KB supersedes, but that the corresponding
// Bulletin archive page on Microsoft Learn lists as superseded by a different
// component in the same bulletin (Excel mis-attribution). For each such pair
// (newKBID, oldKBID), the edge oldKBID → newKBID is removed from
// kbSupersededBy. The correct edge is added separately via
// bulletinArchiveSupersedes.
//
// The Bulletin source is frozen (retired April 2017), so this map is a static
// snapshot derived from the same archive markdown / Excel diff as
// bulletinArchiveSupersedes. The archive page for the newer KB's bulletin
// lives at:
//
//	https://learn.microsoft.com/en-us/security-updates/securitybulletins/<YYYY>/<bulletin-id-lowercase>
//
// Each entry's trailing comment names the new KB's bulletin (which Excel
// mis-attributes to) plus a product/component hint and the old KB's actual
// origin so reviewers can verify the edge against the corresponding archive
// page (the "Updates Replaced" column of the Affected Software table).
//
// Ordering convention: same as bulletinArchiveSupersedes — entries are sorted
// by (bulletin year, bulletin number, KBID), with the primary bulletin taken
// from the first MS<YY>-<NNN> token in the trailing comment. Entries whose
// comment lists several bulletins (e.g., "MS15-091/093/094/...(Win10)") sort
// under the first one. New entries must follow this convention.
var bulletinArchiveSupersedesOverride = map[string][]string{
	"2772930": {"2626416"},            // MS13-032: AD Lightweight Directory Services (Server 2003 SP2); Excel cites MS11-095[2626416] (AD Application Mode, sibling component)
	"2817480": {"2598253"},            // MS13-054: Office 2003 SP3 (GDI+); Excel cites MS12-034[2598253] (different component_kb in archive)
	"2843162": {"2827750"},            // MS13-054: Lync 2010 Attendee user-install (GDI+); Excel cites MS13-041[2827750] (Lync admin-install sibling)
	"2843163": {"2827750"},            // MS13-054: Lync 2010 Attendee admin-install (GDI+); Excel cites MS13-041[2827750] (same sibling mis-attribution)
	"3012168": {"2909213"},            // MS14-084: VBScript 5.6; Excel cites MS14-011[2909213] (different chain in archive)
	"3012172": {"2909212"},            // MS14-084: VBScript 5.7; Excel cites MS14-011[2909212] (different chain in archive)
	"3012176": {"2909210"},            // MS14-084: VBScript 5.8; Excel cites MS14-011[2909210] (different chain in archive)
	"3021952": {"3012176"},            // MS15-009: IE Cumulative; Excel cites MS14-084[3012176] (VBScript 5.8, sibling component)
	"2956138": {"2956058"},            // MS15-022: Office 2010 SP2; Excel cites MS15-012[2956058] (different component_kb in archive)
	"3062577": {"3062577"},            // MS15-062: AD FS 2.0/2.1; Excel claims KB3062577 supersedes itself
	"3081455": {"3081444"},            // MS15-091/093/094/...(Win10): Edge/.NET; Excel cites MS15-093[3081444] (IE 11, sibling chain)
	"3087038": {"3081444"},            // MS15-094: IE Cumulative; Excel cites MS15-093[3081444] (IE 11, sibling chain)
	"3097617": {"3081455"},            // MS15-106/107/109/111(Win10): Edge/IE 11; Excel cites MS15-094/095[3081455] (different component_kb)
	"3105213": {"3096448", "3097617"}, // MS15-112/113/115/118/119/122(Win10): Edge/.NET/IE; Excel cites MS15-107[3096448] and MS15-106[3097617] — sibling chains
	"2899516": {"2553428"},            // MS15-116: Pinyin IME 2010 (Office 2010); Excel cites MS15-033[2553428] (Word 2010, sibling component)
	"2965313": {"3085514"},            // MS15-116: Word 2010 SP2 (Office 2010); Excel cites MS15-110[3085514] (Visio 2010, sibling component)
	"3054793": {"3085583"},            // MS15-116: InfoPath 2013 (Office 2013); Excel cites MS15-110[3085583] (Excel 2013, sibling component)
	"3085584": {"2956151"},            // MS15-116: Access 2013 (Office 2013); Excel cites MS15-022[2956151] (different component_kb)
	"3085614": {"3055033"},            // MS15-116: Project 2010 (Office 2010); Excel cites MS15-081[3055033] (PowerPoint 2010, sibling component)
	"3101360": {"2687413", "3055030"}, // MS15-116: Office 2013 SP1; Excel cites MS13-075[2687413] (Pinyin IME) and MS15-081[3055030] (Word 2013) — sibling components
	"3101370": {"3054929", "3055029"}, // MS15-116: Word 2013 SP1 (Office 2013); Excel cites MS15-081[3054929] (Visio 2013) and [3055029] (PowerPoint 2013) — sibling components
	"3101371": {"3085583"},            // MS15-116: OneNote 2013 (Office 2013); Excel cites MS15-110[3085583] (Excel 2013, sibling component)
	"3101499": {"2956151"},            // MS15-116: Excel 2013 (Office 2013); Excel cites MS15-022[2956151] (different component_kb)
	"3101506": {"3055029"},            // MS15-116: Project 2013 (Office 2013); Excel cites MS15-081[3055029] (PowerPoint 2013, sibling component)
	"3101512": {"3055030"},            // MS15-116: Office 2016; Excel cites MS15-081[3055030] (Word 2013, different product)
	"3101526": {"2553147"},            // MS15-116: Visio 2010 SP2 (Office 2010); Excel cites MS13-042[2553147] (Publisher 2010, sibling component)
	"3116869": {"3105213"},            // MS15-124/125/128/132/133/135(Win10): Edge/IE 11; Excel cites MS15-112[3105213] (different chain in archive)
	"3116900": {"3105211"},            // MS15-124/125/128/132/133/135(Win10 1511): Edge/IE 11; Excel cites MS15-112[3105211] (different chain in archive)
	"3124263": {"3116900"},            // MS16-001/002/005/007/008(Win10 1511): Edge/IE 11; Excel cites MS15-124[3116900] (different chain in archive)
	"3124266": {"3116869"},            // MS16-001/002/005/007/008(Win10): Edge/IE 11; Excel cites MS15-124[3116869] (different chain in archive)
	"3126041": {"3121918"},            // MS16-014: Kerberos/Win-platform; Excel cites MS16-007[3121918] (different component_kb)
	"3137721": {"3133699"},            // MS16-015: Office for Mac 2011 (Excel/Word); Excel cites MS16-004[3133699] (Office for Mac 2011 trio, sibling component)
	"3135988": {"3099862"},            // MS16-035: .NET 3.5.1; Excel cites MS12-025[3099862] (different chain, replaces via MS15-128)
	"2984938": {"3114983"},            // MS16-054: Office 2007 SP3; Excel cites MS16-042[3114983] (Word 2007 SP3, sibling component)
	"2984943": {"3114990"},            // MS16-054: Office 2007 SP3; Excel cites MS16-042[3114990] (Office 2010 SP2, different product)
	"3054984": {"3054841"},            // MS16-054: Office 2010 SP2; Excel cites MS15-046[3054841] (different component_kb in archive)
	"3101520": {"3114993"},            // MS16-054: Office 2010 SP2; Excel cites MS16-042[3114993] (Word 2010 SP2, sibling component)
	"3115016": {"3114937"},            // MS16-054: Office 2013 SP1; Excel cites MS16-042[3114937] (Word 2013, sibling component)
	"3115025": {"3114486"},            // MS16-054: Word 2013 SP1; Excel cites MS16-004[3114486] (Office 2013 SP1, different component_kb)
	"3115094": {"3142577", "3154208"}, // MS16-054: Word 2016; Excel cites MS16-042[3142577] (Word 2016 for Mac) and [3154208] (Word for Mac 2011) — different platforms
	"3115103": {"3114855"},            // MS16-054: Office 2016; Excel cites MS16-029[3114855] (Word 2016, sibling component)
	"3115116": {"3114990"},            // MS16-054: Word 2007 SP3; Excel cites MS16-042[3114990] (Office 2010 SP2, different product)
	"3115121": {"3054848"},            // MS16-054: Office 2010 SP2; Excel cites MS15-046[3054848] (different component_kb)
	"3155776": {"3114982"},            // MS16-054: Word for Mac 2011; Excel cites MS16-042[3114982] (different component_kb in archive)
	"3155777": {"3114987"},            // MS16-054: Word 2016 for Mac; Excel cites MS16-042[3114987] (different component_kb in archive)
	"2596915": {"2687505"},            // MS16-070: Visio Viewer 2007 SP3; Excel cites MS13-023[2687505] (different component_kb in archive)
	"3114740": {"3115116"},            // MS16-070: Visio 2007 SP3; Excel cites MS16-054[3115116] (Word 2007 SP3, sibling component)
	"3114872": {"3115123"},            // MS16-070: Visio 2010 SP2; Excel cites MS16-054[3115123] (Word 2010 SP2, sibling component)
	"3115014": {"3115121"},            // MS16-070: Word Automation Services (SharePoint 2013); Excel cites MS16-054[3115121] (Office 2010 SP2, different product)
	"3115020": {"3115025"},            // MS16-070: Visio 2013 SP1; Excel cites MS16-054[3115025] (Word 2013, sibling component)
	"3115041": {"3115094"},            // MS16-070: Visio 2016 (Office 2016); Excel cites MS16-054[3115094] (Word 2016, sibling component)
	"3115107": {"3114421"},            // MS16-070: Excel 2007 SP3; Excel cites MS16-004[3114421] (Visio 2007 SP3, sibling component)
	"3115111": {"3115115"},            // MS16-070: Office Compatibility Pack SP3; Excel cites MS16-054[3115115] (different component_kb)
	"3115130": {"3114402"},            // MS16-070: Excel 2010 SP2; Excel cites MS16-004[3114402] (Visio 2010 SP2, sibling component)
	"3115144": {"3114511"},            // MS16-070: Office 2016; Excel cites MS16-004[3114511] (Visio 2016, sibling component)
	"3115170": {"3114888"},            // MS16-070: Office Web Apps Server 2013; Excel cites MS16-042[3114888] (Excel 2010 SP2, different product)
	"3115194": {"3115132"},            // MS16-070: Office Compatibility Pack SP3; Excel cites MS16-054[3115132] (different component_kb)
	"3115195": {"3115121"},            // MS16-070: Word 2007 SP3; Excel cites MS16-054[3115121] (Office 2010 SP2, different product)
	"3115196": {"3115116"},            // MS16-070: Word Automation Services (SharePoint 2010); Excel cites MS16-054[3115116] (Word 2007 SP3, different product)
	"3115198": {"3114888"},            // MS16-070: Office 2010 SP2; Excel cites MS16-042[3114888] (Excel 2010 SP2, sibling component)
	"3115243": {"3114489"},            // MS16-070: Word 2010 SP2; Excel cites MS16-004[3114489] (Visio 2013, different product)
	"3115244": {"3115121"},            // MS16-070: Office Web Apps 2010 SP2; Excel cites MS16-054[3115121] (Office 2010 SP2, different product)
	"3165798": {"3114895"},            // MS16-070: Word 2016 for Mac; Excel cites MS16-042[3114895] (different component_kb in archive)
	"3115487": {"3115118"},            // MS16-107: PowerPoint 2013 SP1; Excel cites MS16-088[3115118] (PowerPoint 2010 SP2, different product)
	"3118268": {"3115262"},            // MS16-107: Office 2013 SP1; Excel cites MS16-088[3115262] (Excel 2013, sibling component)
	"3118280": {"3115118"},            // MS16-107: Outlook 2013 SP1; Excel cites MS16-088[3115118] (PowerPoint 2010 SP2, different product)
	"3118284": {"3115452"},            // MS16-107: Excel 2013 SP1; Excel cites MS16-099[3115452] (different component_kb in archive)
	"3118292": {"3115272"},            // MS16-107: Office 2016; Excel cites MS16-088[3115272] (Excel 2016, sibling component)
	"3193418": {"3033889"},            // MS16-130: Windows Server 2008/Vista; Excel cites MS15-020[3033889] (different component_kb)
	"3196718": {"3184122"},            // MS16-130: Windows Server 2008/Vista; Excel cites MS16-116[3184122] (different component_kb)
	"3198218": {"3190847"},            // MS16-131: Windows Vista SP2; Excel cites MS16-122[3190847] (different component_kb)
	"3198798": {"3118307"},            // MS16-133: Office for Mac (Excel/Word 2016 for Mac); Excel cites MS16-121[3118307] (different component_kb)
	"3194371": {"3177725"},            // MS16-135: Windows Server 2008; Excel cites MS16-098[3177725] (different component_kb)
	"3198510": {"3081320"},            // MS16-137: Windows Server 2008; Excel cites MS15-121[3081320] (different component_kb)
	"3178688": {"3115131"},            // MS17-013: Office 2010 SP2; Excel cites MS16-097[3115131] (Office 2010 SP2, different chain)
}

// bulletinArchiveKBNotApplicable lists (componentKB → []CVE) pairs whose
// cell in the Bulletin archive markdown per-CVE Severity Ratings matrix
// table is one of the two semantically-equivalent NA markers Microsoft
// uses:
//
//   - "Not applicable" — the dominant phrasing across the archive.
//   - "Not affected"   — a legacy spelling that appears in a small set
//     of MS00-MS16 bulletins (notably MS16-106). Same semantic: the
//     row's product is not affected by the CVE.
//
// Other cell markers that look superficially similar must NOT be
// treated as NA, because they describe products that ARE affected:
//
//   - "No severity rating" / "Defense in Depth" — Microsoft's footnote
//     (e.g. MS13-004) explains the product is affected by the
//     vulnerability, the known attack vectors are merely blocked in a
//     default configuration, and customers should still install the
//     update. CVE attribution must remain for these rows.
//
// The TestBulletinArchiveNotApplicable / KB-keyed table in
// bulletin_test.go contains a regression-guard case for each marker
// path (one "Not applicable", one "Not affected").
//
// KB-keyed entries are non-lossy only when every xlsx row sharing the
// KB has an NA cell for the CVE; pairs where some rows are NA and
// others have an applicable severity across the same bulletin would
// over-broadly drop CVE attribution on the affected rows, so those are
// deliberately omitted from this map.
//
// Inline "// MS<id>: <product>" comments identify the source bulletin(s)
// for review traceability — see bulletinArchiveSupersedes for the same convention.
var bulletinArchiveKBNotApplicable = map[string][]string{
	// MS08-044: Microsoft Office 2003 Service Pack 2
	"921598": {"CVE-2008-3020"},
	// MS06-060: Microsoft Word 2003 SP1/SP2 (+ Office 2003 SP1/SP2 row pair). Per the
	// archive markdown's per-CVE table the Word 2003 column is "Not applicable" for
	// CVE-2006-4693. (Manually added because gen_static_map.py does not yet
	// recognise MS06-060's "Vulnerability Identifiers" header layout.)
	"923088": {"CVE-2006-4693"},
	// MS06-060: Microsoft Word 2002 SP3 (Office XP SP3) + Microsoft Works Suite
	// 2004/2005/2006. The bulletin's footnote states "The Microsoft Works Suite
	// 2004/2005/2006 severity rating is the same as the Microsoft Word 2002 severity
	// rating", and BulletinSearch.xlsx confirms all four rows share component_kb
	// 923089. The Word 2002 column is NA for CVE-2006-4693.
	"923089": {"CVE-2006-4693"},
	// MS06-060: Microsoft Word 2000 SP3 (Office 2000 SP3). Word 2000 column NA
	// for CVE-2006-4693.
	"923090": {"CVE-2006-4693"},
	// MS09-010: Microsoft Windows 2000 Service Pack 4 (+ 4 variants)
	"923561": {"CVE-2009-0088"},
	// MS06-060: Microsoft Office v. X for Mac (Office X for Mac suite row). Word
	// for Mac column NA for CVE-2006-3651 and CVE-2006-4534.
	"924998": {"CVE-2006-3651", "CVE-2006-4534"},
	// MS06-060: Microsoft Word 2004 for Mac (Office 2004 for Mac suite row).
	// Word for Mac column NA for CVE-2006-3651 and CVE-2006-4534.
	"924999": {"CVE-2006-3651", "CVE-2006-4534"},
	// MS08-040: Microsoft SQL Server 2000 Desktop Engine (WMSDE) (+ 2 variants)
	"941203": {"CVE-2008-0086", "CVE-2008-0106"},
	// MS07-064: DirectX 9.0 on Microsoft Windows 2000 Service Pack 4 (+ 7 variants)
	"941568": {"CVE-2007-3901"},
	// MS07-069: Internet Explorer 5.01 Service Pack 4 on Microsoft Windows 2000 Service Pack 4
	"942615": {"CVE-2007-3903", "CVE-2007-5344"},
	// MS09-043: Microsoft Office 2003 Web Components Service Pack 1 for the 2007 Microsoft Office System
	"947318": {"CVE-2009-1534"},
	// MS09-043: Microsoft Office 2003 Service Pack 3 (+ 1 variant)
	"947319": {"CVE-2009-1534"},
	// MS09-043: Microsoft Office 2000 Web Components Service Pack 3
	"947320": {"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"},
	// MS09-043: Microsoft Internet Security and Acceleration Server 2004 Standard Edition Service Pack 3 (+ 3 variants)
	"947826": {"CVE-2009-1534"},
	// MS08-040: SQL Server 2005 Service Pack 1 and SQL Server 2005 Service Pack 2 (+ 4 variants)
	"948109": {"CVE-2008-0086"},
	// MS08-040: SQL Server 2000 Service Pack 4 (+ 2 variants)
	"948110": {"CVE-2008-0106"},
	// MS08-040: SQL Server 7.0 Service Pack 4 (+ 1 variant)
	"948113": {"CVE-2008-0086", "CVE-2008-0106"},
	// MS08-051: Microsoft Office PowerPoint Viewer 2003
	"949041": {"CVE-2008-1455"},
	// MS08-070: Microsoft Office Project 2003 Service Pack 3
	"949045": {"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4254", "CVE-2008-4256"},
	// MS08-070: Microsoft Office Project 2007 and Microsoft Office Project 2007 Service Pack 1
	"949046": {"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254", "CVE-2008-4256"},
	// MS08-051: Microsoft Office PowerPoint 2000 Service Pack 3 (+ 5 variants)
	"949785": {"CVE-2008-0120", "CVE-2008-0121"},
	// MS08-031: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4
	"950759": {"CVE-2008-1442"},
	// MS08-036: Windows Vista and Windows Vista Service Pack 1 (+ 4 variants)
	"950762": {"CVE-2008-1440"},
	// MS08-069: Microsoft XML Core Services 5.0 on Microsoft Office 2003 Service Pack 3 (+ 1 variant)
	"951535": {"CVE-2007-0099", "CVE-2008-4029"},
	// MS08-069: Microsoft XML Core Services 5.0 on 2007 Microsoft Office System and 2007 Microsoft Office System Service Pack 1 (+ 2 variants)
	"951550": {"CVE-2007-0099", "CVE-2008-4029"},
	// MS08-069: Microsoft XML Core Services 5.0 on Microsoft Office SharePoint Server 2007 and Microsoft Office SharePoint Server 200... (+ 2 variants)
	"951597": {"CVE-2007-0099", "CVE-2008-4029"},
	// MS08-033: Microsoft Windows 2000 Service Pack 4 with DirectX 7.0 (+ 11 variants)
	"951698": {"CVE-2008-0011", "CVE-2008-1444"},
	// MS09-012: Microsoft Windows 2000 Service Pack 4 (+ 10 variants)
	"952004": {"CVE-2009-0078", "CVE-2009-0079", "CVE-2009-0080"},
	// MS08-076: Windows Media Services 2008 on Windows Server 2008 for 32-bit Systems and Windows Server 2008 for 32-bit Systems Serv... (+ 1 variant)
	"952068": {"CVE-2008-3010"},
	// MS08-037: Windows XP Service Pack 2 and Windows XP Service Pack 3 (+ 3 variants)
	"953230": {"CVE-2008-1447", "CVE-2008-1454"},
	// MS09-061: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4 (+ 7 variants)
	"953297": {"CVE-2009-0091", "CVE-2009-2497"},
	// MS09-061: Microsoft .NET Framework 1.1 Service Pack 1 on Windows Server 2003 Service Pack 2
	"953298": {"CVE-2009-0091", "CVE-2009-2497"},
	// MS08-039: Microsoft Exchange Server 2003 Service Pack 2 (+ 2 variants)
	"953747": {"CVE-2008-2247", "CVE-2008-2248"},
	// MS08-051: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1
	"954038": {"CVE-2008-0120", "CVE-2008-0121"},
	// MS08-069: Microsoft XML Core Services 4.0 when installed on Microsoft Windows 2000 Service Pack 4 (+ 14 variants)
	"954430": {"CVE-2007-0099"},
	// MS08-069: Microsoft XML Core Services 6.0 when installed on Microsoft Windows 2000 Service Pack 4 (+ 11 variants)
	"954459": {"CVE-2007-0099", "CVE-2008-4029"},
	// MS08-051: Microsoft Office 2004 for Mac
	"956343": {"CVE-2008-0120", "CVE-2008-0121"},
	// MS08-058: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 9 variants)
	"956390": {"CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476"},
	// MS09-062: Microsoft .NET Framework 2.0 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4 (+ 1 variant)
	"957488": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS08-070: Microsoft Office FrontPage 2002 Service Pack 3
	"957797": {"CVE-2008-3704", "CVE-2008-4252", "CVE-2008-4254", "CVE-2008-4255", "CVE-2008-4256"},
	// MS09-005: Microsoft Office Visio 2007 Service Pack 1
	"957831": {"CVE-2009-0097"},
	// MS08-073: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 16 variants)
	"958215": {"CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260", "CVE-2008-4261"},
	// MS08-070: Microsoft Visual Studio .NET 2002 Service Pack 1
	"958392": {"CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254"},
	// MS08-070: Microsoft Visual Studio .NET 2003 Service Pack 1
	"958393": {"CVE-2008-4252", "CVE-2008-4253", "CVE-2008-4254"},
	// MS09-001: Windows Vista and Windows Vista Service Pack 1 (+ 4 variants)
	"958687": {"CVE-2008-4834"},
	// MS09-006: Windows XP Professional x64 Edition Service Pack 2 (+ 8 variants)
	"958690": {"CVE-2009-0083"},
	// MS09-062: Microsoft Internet Explorer 6 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4 (+ 10 variants)
	"958869": {"CVE-2009-2500", "CVE-2009-2501", "CVE-2009-2502", "CVE-2009-2503", "CVE-2009-2504", "CVE-2009-2518", "CVE-2009-2528", "CVE-2009-3126"},
	// MS09-003: Microsoft Exchange Server 2007 Service Pack 1
	"959241": {"CVE-2009-0099"},
	// MS09-010: Microsoft Office Converter Pack
	"960476": {"CVE-2008-4841", "CVE-2009-0087", "CVE-2009-0235"},
	// MS09-010: Windows XP Service Pack 2 (+ 3 variants)
	"960477": {"CVE-2008-4841", "CVE-2009-0088", "CVE-2009-0235"},
	// MS09-013: Windows Vista Service Pack 1 (+ 4 variants)
	"960803": {"CVE-2009-0089"},
	// MS09-022: Windows XP Service Pack 2 and Windows XP Service Pack 3 (+ 9 variants)
	"961501": {"CVE-2009-0228"},
	// MS09-016: Microsoft Internet Security and Acceleration Server 2004 Service Pack 3
	"961759": {"CVE-2009-0237"},
	// MS09-008: Windows Server 2008 for 32-bit Systems (+ 1 variant)
	"962238": {"CVE-2009-0093", "CVE-2009-0094"},
	// MS09-014: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 16 variants)
	"963027": {"CVE-2008-2540", "CVE-2009-0551", "CVE-2009-0552", "CVE-2009-0553"},
	// MS09-017: Microsoft Works 8.5
	"967043": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-017: Microsoft Works 9
	"967044": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-017: Microsoft Office PowerPoint 2000 Service Pack 3 (+ 4 variants)
	"967340": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-048: Microsoft Windows 2000 Service Pack 4 (+ 5 variants)
	"967723": {"CVE-2009-1925"},
	// MS09-043: Microsoft Office Small Business Accounting 2006
	"968377": {"CVE-2009-1534"},
	// MS09-025: Windows Vista, Windows Vista Service Pack 1, and Windows Vista Service Pack 2 (+ 4 variants)
	"968537": {"CVE-2009-1126"},
	// MS09-043: Microsoft Visual Studio .NET 2003 Service Pack 1
	"969172": {"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"},
	// MS09-021: Microsoft Office Excel 2000 Service Pack 3 (+ 7 variants)
	"969462": {"CVE-2009-0549", "CVE-2009-0558", "CVE-2009-0559", "CVE-2009-1134"},
	// MS09-027: Microsoft Office Word 2000 Service Pack 3 (+ 1 variant)
	"969514": {"CVE-2009-0563", "CVE-2009-0565"},
	// MS09-027: Microsoft Office Word Viewer 2003 Service Pack 3 (+ 1 variant)
	"969614": {"CVE-2009-0565"},
	// MS09-017: PowerPoint Viewer 2003
	"969615": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-017: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1 and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"969618": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-017: Microsoft Office 2004 for Mac
	"969661": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-021: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1 and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"969679": {"CVE-2009-0549", "CVE-2009-0558", "CVE-2009-0559"},
	// MS09-021: Microsoft Office Excel Viewer
	"969686": {"CVE-2009-0549", "CVE-2009-0558", "CVE-2009-0559"},
	// MS09-021: Microsoft Office SharePoint Server 2007 Service Pack 1 and Microsoft Office SharePoint Server 2007 Service Pack 2 (32... (+ 1 variant)
	"969737": {"CVE-2009-0549", "CVE-2009-0557", "CVE-2009-0558", "CVE-2009-0559", "CVE-2009-0560", "CVE-2009-1134"},
	// MS09-018: Active Directory on Windows Server 2003 Service Pack 2 (+ 2 variants)
	"969805": {"CVE-2009-1138"},
	// MS09-039: Windows Server 2003 Service Pack 2 (+ 2 variants)
	"969883": {"CVE-2009-1924"},
	// MS09-019: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 24 variants)
	"969897": {"CVE-2007-3091", "CVE-2009-1140", "CVE-2009-1141", "CVE-2009-1528", "CVE-2009-1529", "CVE-2009-1530", "CVE-2009-1531", "CVE-2009-1532"},
	// MS09-065: Windows Vista, Windows Vista Service Pack 1, and Windows Vista Service Pack 2 (+ 4 variants)
	"969947": {"CVE-2009-2514"},
	// MS09-017: PowerPoint Viewer 2007 Service Pack 1 and PowerPoint Viewer 2007 Service Pack 2
	"970059": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-061: Microsoft Silverlight 2 when installed on Mac (+ 2 variants)
	"970363": {"CVE-2009-0090", "CVE-2009-0091"},
	// MS09-018: Active Directory Application Mode (ADAM) when installed on Windows XP Professional Service Pack 2 and Windows XP Prof... (+ 1 variant)
	"970437": {"CVE-2009-1138"},
	// MS09-020: Microsoft Internet Information Services (IIS) 5.0 on Microsoft Windows 2000 Service Pack 4 (+ 5 variants)
	"970483": {"CVE-2009-1122", "CVE-2009-1535"},
	// MS09-062: SQL Server 2005 Service Pack 3 (+ 2 variants)
	"970892": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: SQL Server 2005 Service Pack 2 (+ 2 variants)
	"970895": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-044: Microsoft Windows 2000 Service Pack 4 (+ 8 variants)
	"970927": {"CVE-2009-1929"},
	// MS09-062: Microsoft Visual Studio .NET 2003 Service Pack 1
	"971022": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Visual Studio 2005 Service Pack 1
	"971023": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Visual FoxPro 8.0 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4
	"971104": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Visual FoxPro 9.0 Service Pack 2 when installed on Microsoft Windows 2000 Service Pack 4
	"971105": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4
	"971108": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows 2000 Service Pack 4
	"971111": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Report Viewer 2005 Service Pack 1 Redistributable Package
	"971117": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Report Viewer 2008 Redistributable Package
	"971118": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-043: Microsoft BizTalk Server 2002
	"971388": {"CVE-2009-0562", "CVE-2009-1136", "CVE-2009-2496"},
	// MS10-012: Microsoft Windows 2000 Service Pack 4 (+ 5 variants)
	"971468": {"CVE-2010-0021"},
	// MS09-058: Microsoft Windows 2000 Service Pack 4 (+ 14 variants)
	"971486": {"CVE-2009-2516", "CVE-2009-2517"},
	// MS09-017: Microsoft Office 2008 for Mac
	"971822": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-017: Open XML File Format Converter for Mac
	"971824": {"CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222", "CVE-2009-0223", "CVE-2009-0225", "CVE-2009-0226", "CVE-2009-0227", "CVE-2009-0556", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130", "CVE-2009-1131", "CVE-2009-1137"},
	// MS09-062: Microsoft Visual Studio 2008
	"972221": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-034: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4
	"972260": {"CVE-2009-1917"},
	// MS09-047: Windows Media Services 9.1 on Windows Server 2003 Service Pack 2 (+ 3 variants)
	"972554": {"CVE-2009-2499"},
	// MS09-062: Microsoft Office 2003 Service Pack 3 (+ 1 variant)
	"972580": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: 2007 Microsoft Office System Service Pack 1 (+ 5 variants)
	"972581": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-067: Microsoft Office Excel 2003 Service Pack 3 (+ 1 variant)
	"972652": {"CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3130", "CVE-2009-3133"},
	// MS09-067: Microsoft Office Excel Viewer 2003 Service Pack 3
	"973484": {"CVE-2009-3130", "CVE-2009-3133"},
	// MS09-062: Microsoft Works 8.5
	"973636": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-067: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1 and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"973704": {"CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3130", "CVE-2009-3133"},
	// MS09-067: Microsoft Office Excel Viewer Service Pack 1 and Microsoft Office Excel Viewer Service Pack 2
	"973707": {"CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3130", "CVE-2009-3133"},
	// MS09-047: Microsoft Media Foundation on Windows Vista, Windows Vista Service Pack 1, and Windows Vista Service Pack 2 (+ 3 variants)
	"973812": {"CVE-2009-2498"},
	// MS09-044: Remote Desktop Connection Client for Mac 2.0
	"974283": {"CVE-2009-1929"},
	// MS09-071: Microsoft Windows 2000 Service Pack 4 (+ 15 variants)
	"974318": {"CVE-2009-2505", "CVE-2009-3677"},
	// MS09-061: Microsoft .NET Framework 1.0 Service Pack 3 on Windows XP Tablet Edition 2005 Service Pack 2, Windows XP Tablet Editi... (+ 28 variants)
	"974378": {"CVE-2009-0090", "CVE-2009-0091", "CVE-2009-2497"},
	// MS09-054: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 12 variants)
	"974455": {"CVE-2009-1547", "CVE-2009-2530", "CVE-2009-2531"},
	// MS09-061: Microsoft .NET Framework 2.0 on Windows Vista (+ 3 variants)
	"974468": {"CVE-2009-0090", "CVE-2009-0091"},
	// MS09-061: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Server 2008 for 32-bit Systems Service Pack 2 (+ 2 variants)
	"974470": {"CVE-2009-0090", "CVE-2009-0091"},
	// MS09-062: Microsoft Office Project 2002 Service Pack 1
	"974811": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-053: Microsoft Internet Information Services 7.0 on Windows Vista, Windows Vista Service Pack 1, and Windows Vista Service... (+ 4 variants)
	"975254": {"CVE-2009-3023"},
	// MS09-062: Microsoft Platform SDK Redistributable: GDI+
	"975337": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-062: Microsoft Visio 2002 Service Pack 2
	"975365": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS10-004: Microsoft Office PowerPoint 2002 Service Pack 3 (+ 1 variant)
	"975416": {"CVE-2010-0029", "CVE-2010-0033", "CVE-2010-0034"},
	// MS09-062: Microsoft Forefront Client Security 1.0 when installed on Microsoft Windows 2000 Service Pack 4
	"975962": {"CVE-2009-2518", "CVE-2009-2528"},
	// MS09-072: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 28 variants)
	"976325": {"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3672", "CVE-2009-3673", "CVE-2009-3674"},
	// MS10-024: Microsoft Exchange Server 2003 Service Pack 2
	"976702": {"CVE-2010-0025"},
	// MS10-024: Microsoft Exchange Server 2000 Service Pack 3
	"976703": {"CVE-2010-0024"},
	// MS09-067: Microsoft Office 2008 for Mac
	"976828": {"CVE-2009-3128"},
	// MS09-067: Microsoft Office 2004 for Mac
	"976830": {"CVE-2009-3128"},
	// MS09-067: Open XML File Format Converter for Mac
	"976831": {"CVE-2009-3128"},
	// MS10-015: Windows XP Professional x64 Edition Service Pack 2 (+ 6 variants)
	"977165": {"CVE-2010-0232", "CVE-2010-0233"},
	// MS10-002: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 29 variants)
	"978207": {"CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0244", "CVE-2010-0245", "CVE-2010-0246", "CVE-2010-0247", "CVE-2010-0248", "CVE-2010-0249"},
	// MS10-006: Microsoft Windows 2000 Service Pack 4 (+ 14 variants)
	"978251": {"CVE-2010-0016", "CVE-2010-0017"},
	// MS10-017: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1 and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"978380": {"CVE-2010-0257", "CVE-2010-0262", "CVE-2010-0264"},
	// MS10-017: Microsoft Office Excel Viewer Service Pack 1 and Microsoft Office Excel Viewer Service Pack 2
	"978383": {"CVE-2010-0257", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0264"},
	// MS10-033: Windows Media Format Runtime 9 on Microsoft Windows 2000 Service Pack 4 (+ 4 variants)
	"978695": {"CVE-2010-1880"},
	// MS10-058: Windows Vista Service Pack 2 (+ 4 variants)
	"978886": {"CVE-2010-1893"},
	// MS10-033: Windows Media Encoder 9 x86 when installed on Microsoft Windows 2000 Service Pack 4 (+ 7 variants)
	"979332": {"CVE-2010-1880"},
	// MS10-017: Microsoft Office SharePoint Server 2007 Service Pack 1 (32-bit editions) and Microsoft Office SharePoint Server 2007 ... (+ 1 variant)
	"979439": {"CVE-2010-0257", "CVE-2010-0258", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0264"},
	// MS10-039: Microsoft Office InfoPath 2007 Service Pack 1 and Microsoft Office InfoPath 2007 Service Pack 2
	"979441": {"CVE-2010-0817", "CVE-2010-1264"},
	// MS10-039: Microsoft Office SharePoint Server 2007 Service Pack 1 and Microsoft Office SharePoint Server 2007 Service Pack 2 (32... (+ 1 variant)
	"979445": {"CVE-2010-0817", "CVE-2010-1264"},
	// MS10-033: Asycfilt.dll (COM component) on Microsoft Windows 2000 Service Pack 4 (+ 12 variants)
	"979482": {"CVE-2010-1880"},
	// MS10-032: Windows 7 for 32-bit Systems (+ 3 variants)
	"979559": {"CVE-2010-0484"},
	// MS10-004: Microsoft Office 2004 for Mac
	"979674": {"CVE-2010-0029", "CVE-2010-0030", "CVE-2010-0032", "CVE-2010-0033", "CVE-2010-0034"},
	// MS10-021: Microsoft Windows 2000 Service Pack 4 (+ 16 variants)
	"979683": {"CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237", "CVE-2010-0238", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810"},
	// MS10-033: Windows Media Encoder 9 x64 when installed on Windows XP Professional x64 Edition Service Pack 2 (+ 6 variants)
	"979902": {"CVE-2010-1880"},
	// MS10-017: Microsoft Office Excel 2002 Service Pack 3 (+ 2 variants)
	"980150": {"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0263", "CVE-2010-0264"},
	// MS10-018: Internet Explorer 5.01 Service Pack 4 when installed on Microsoft Windows 2000 Service Pack 4 (+ 28 variants)
	"980182": {"CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0490", "CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0494", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807"},
	// MS10-034: Microsoft Windows 2000 Service Pack 4 (+ 2 variants)
	"980195": {"CVE-2010-0811"},
	// MS10-020: Microsoft Windows 2000 Service Pack 4 (+ 10 variants)
	"980232": {"CVE-2009-3676", "CVE-2010-0270", "CVE-2010-0476", "CVE-2010-0477"},
	// MS10-049: Windows Vista Service Pack 1 and Windows Vista Service Pack 2 (+ 8 variants)
	"980436": {"CVE-2010-2566"},
	// MS10-017: Microsoft Office 2004 for Mac
	"980837": {"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0263"},
	// MS10-017: Microsoft Office 2008 for Mac
	"980839": {"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262"},
	// MS10-017: Open XML File Format Converter for Mac
	"980840": {"CVE-2010-0257", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262"},
	// MS10-039: Microsoft Office InfoPath 2003 Service Pack 3
	"980923": {"CVE-2010-0817", "CVE-2010-1264"},
	// MS10-019: Authenticode Signature Verification 5.1 (+ 5 variants)
	"981210": {"CVE-2010-0486", "CVE-2010-0487"},
	// MS10-024: Microsoft Exchange Server 2007 Service Pack 2 for x64-based Systems
	"981383": {"CVE-2010-0025"},
	// MS10-024: Microsoft Exchange Server 2010 for x64-based Systems
	"981401": {"CVE-2010-0025"},
	// MS10-024: Microsoft Exchange Server 2007 Service Pack 1 for x64-based Systems
	"981407": {"CVE-2010-0025"},
	// MS10-047: Windows XP Service Pack 3 (+ 9 variants)
	"981852": {"CVE-2010-1888", "CVE-2010-1889", "CVE-2010-1890"},
	// MS10-073: Windows XP Service Pack 3 (+ 8 variants)
	"981957": {"CVE-2010-2549"},
	// MS10-054: Windows XP Service Pack 3 (+ 4 variants)
	"982214": {"CVE-2010-2551", "CVE-2010-2552"},
	// MS10-038: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 1 and Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"982331": {"CVE-2010-0822", "CVE-2010-0824", "CVE-2010-1245", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1249", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1254"},
	// MS10-038: Microsoft Office Excel Viewer Service Pack 1 and Microsoft Office Excel Viewer Service Pack 2
	"982333": {"CVE-2010-0822", "CVE-2010-0824", "CVE-2010-1245", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1249", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1253", "CVE-2010-1254"},
	// MS10-044: Microsoft Office Access 2007 Service Pack 1 and Microsoft Office Access 2007 Service Pack 2
	"982335": {"CVE-2010-1881"},
	// MS10-035: Internet Explorer 6 Service Pack 1 when installed on Microsoft Windows 2000 Service Pack 4 (+ 15 variants)
	"982381": {"CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1260", "CVE-2010-1261"},
	// MS10-060: Microsoft Silverlight 2 when installed on Mac (+ 2 variants)
	"982926": {"CVE-2010-0019"},
	// MS10-060: Microsoft .NET Framework 3.5 when installed on Windows XP Service Pack 3 (+ 9 variants)
	"983582": {"CVE-2010-0019"},
	// MS10-060: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems (+ 3 variants)
	"983590": {"CVE-2010-0019"},
	// MS10-038: Microsoft Office Excel 2003 Service Pack 3 (+ 3 variants)
	"2027452": {"CVE-2010-0822", "CVE-2010-0824", "CVE-2010-1245", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1249", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1253", "CVE-2010-1254"},
	// MS10-038: Microsoft Office 2008 for Mac
	"2028864": {"CVE-2010-0824", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1251", "CVE-2010-1252", "CVE-2010-1254"},
	// MS10-038: Microsoft Office 2004 for Mac
	"2028866": {"CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1254"},
	// MS10-038: Open XML File Format Converter for Mac
	"2078051": {"CVE-2010-0824", "CVE-2010-1246", "CVE-2010-1247", "CVE-2010-1248", "CVE-2010-1251", "CVE-2010-1252"},
	// MS10-056: Microsoft Works 9
	"2092914": {"CVE-2010-1901", "CVE-2010-1902", "CVE-2010-1903"},
	// MS10-065: Internet Information Services 5.1 on Windows XP Service Pack 3 (+ 13 variants)
	"2124261": {"CVE-2010-2730", "CVE-2010-2731"},
	// MS10-048: Windows Vista Service Pack 1 and Windows Vista Service Pack 2 (+ 8 variants)
	"2160329": {"CVE-2010-1894", "CVE-2010-1895", "CVE-2010-1896"},
	// MS10-053: Internet Explorer 6 for Windows XP Service Pack 3 (+ 26 variants)
	"2183461": {"CVE-2010-2557", "CVE-2010-2559"},
	// MS10-060: Microsoft .NET Framework 2.0 Service Pack 1 on Windows Vista Service Pack 1 (+ 29 variants)
	"2265906": {"CVE-2010-0019"},
	// MS10-056: Microsoft Office Word 2007 Service Pack 2
	"2269638": {"CVE-2010-1903"},
	// MS10-065: Internet Information Services 7.5 on Windows 7 for 32-bit Systems (+ 3 variants)
	"2271195": {"CVE-2010-1899", "CVE-2010-2731"},
	// MS10-056: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2277947": {"CVE-2010-1903"},
	// MS10-056: Microsoft Office 2008 for Mac
	"2284162": {"CVE-2010-1903"},
	// MS10-056: Microsoft Office 2004 for Mac
	"2284171": {"CVE-2010-1903"},
	// MS10-056: Open XML File Format Converter for Mac
	"2284179": {"CVE-2010-1903"},
	// MS10-105: Microsoft Office 2007 Service Pack 2
	"2288931": {"CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950"},
	// MS10-105: Microsoft Office 2010 (32-bit editions) (+ 1 variant)
	"2289078": {"CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950"},
	// MS10-087: Microsoft Office 2007 Service Pack 2
	"2289158": {"CVE-2010-2573", "CVE-2010-3336"},
	// MS10-087: Microsoft Office 2010 (32-bit editions) (+ 1 variant)
	"2289161": {"CVE-2010-2573", "CVE-2010-3336"},
	// MS10-105: Microsoft Office 2003 Service Pack 3
	"2289163": {"CVE-2010-3947", "CVE-2010-3949", "CVE-2010-3950", "CVE-2010-3951", "CVE-2010-3952"},
	// MS10-087: Microsoft Office XP Service Pack 3
	"2289169": {"CVE-2010-3337"},
	// MS10-087: Microsoft Office 2003 Service Pack 3
	"2289187": {"CVE-2010-3336", "CVE-2010-3337"},
	// MS10-065: Internet Information Services 5.1 on Windows XP Service Pack 3
	"2290570": {"CVE-2010-1899", "CVE-2010-2730"},
	// MS10-103: Microsoft Publisher 2003 Service Pack 3 (+ 3 variants)
	"2292970": {"CVE-2010-2569", "CVE-2010-2571", "CVE-2010-3954", "CVE-2010-3955"},
	// MS10-079: Microsoft Word 2003 Service Pack 3 (+ 5 variants)
	"2293194": {"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"},
	// MS10-080: Microsoft Excel 2002 Service Pack 3 (+ 2 variants)
	"2293211": {"CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3232", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240", "CVE-2010-3241", "CVE-2010-3242"},
	// MS10-088: Microsoft Office 2004 for Mac
	"2293386": {"CVE-2010-2572"},
	// MS10-080: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2344875": {"CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3241", "CVE-2010-3242"},
	// MS10-079: Microsoft Word Viewer
	"2345009": {"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220"},
	// MS10-079: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2345043": {"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221"},
	// MS10-080: Microsoft Excel Viewer Service Pack 2
	"2345088": {"CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3241", "CVE-2010-3242"},
	// MS10-072: Microsoft SharePoint Foundation 2010
	"2345322": {"CVE-2010-3243"},
	// MS10-072: Microsoft Groove Server 2010
	"2346298": {"CVE-2010-3243"},
	// MS10-072: Microsoft Office Web Apps
	"2346411": {"CVE-2010-3243"},
	// MS10-071: Internet Explorer 6 for Windows XP Service Pack 3 (+ 26 variants)
	"2360131": {"CVE-2010-0808", "CVE-2010-3243", "CVE-2010-3324", "CVE-2010-3326", "CVE-2010-3329"},
	// MS11-011: Windows XP Professional x64 Edition Service Pack 2 (+ 12 variants)
	"2393802": {"CVE-2011-0045"},
	// MS10-088: Microsoft PowerPoint Viewer 2007 Service Pack 2
	"2413381": {"CVE-2010-2572"},
	// MS10-090: Internet Explorer 6 for Windows XP Service Pack 3 (+ 26 variants)
	"2416400": {"CVE-2010-3340", "CVE-2010-3345"},
	// MS10-079: Microsoft Office 2004 for Mac; MS10-080: Microsoft Office 2004 for Mac
	"2422343": {"CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3239", "CVE-2010-3240"},
	// MS10-079: Microsoft Office 2008 for Mac; MS10-080: Microsoft Office 2008 for Mac
	"2422352": {"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221", "CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240"},
	// MS10-079: Open XML File Format Converter for Mac; MS10-080: Open XML File Format Converter for Mac
	"2422398": {"CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218", "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221", "CVE-2010-3230", "CVE-2010-3233", "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3237", "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240"},
	// MS10-087: Microsoft Office 2004 for Mac
	"2423930": {"CVE-2010-3337"},
	// MS11-013: Windows 7 for 32-bit Systems and Windows 7 for 32-bit Systems Service Pack 1 (+ 3 variants)
	"2425227": {"CVE-2011-0043"},
	// MS10-105: Microsoft Works 9
	"2431831": {"CVE-2010-3945", "CVE-2010-3946", "CVE-2010-3949", "CVE-2010-3951", "CVE-2010-3952"},
	// MS10-098: Windows XP Service Pack 3 (+ 12 variants)
	"2436673": {"CVE-2010-3941", "CVE-2010-3944"},
	// MS11-074: Microsoft Office SharePoint Server 2007 Service Pack 2 (32-bit editions) (+ 4 variants)
	"2451858": {"CVE-2011-0653", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1892", "CVE-2011-1893"},
	// MS10-087: Microsoft Office for Mac 2011
	"2454823": {"CVE-2010-2573", "CVE-2010-3334", "CVE-2010-3337"},
	// MS11-021: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2466156": {"CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0979", "CVE-2011-0980"},
	// MS11-021: Microsoft Excel Viewer Service Pack 2
	"2466158": {"CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0980"},
	// MS10-087: Open XML File Format Converter for Mac
	"2476511": {"CVE-2010-2573", "CVE-2010-3337"},
	// MS10-087: Microsoft Office 2008 for Mac
	"2476512": {"CVE-2010-2573", "CVE-2010-3337"},
	// MS11-013: Windows XP Service Pack 3 (+ 4 variants)
	"2478971": {"CVE-2011-0091"},
	// MS11-012: Windows 7 for 32-bit Systems and Windows 7 for 32-bit Systems Service Pack 1 (+ 3 variants)
	"2479628": {"CVE-2011-0087"},
	// MS11-015: Windows XP Service Pack 3 (+ 2 variants)
	"2479943": {"CVE-2011-0032", "CVE-2011-0042"},
	// MS11-003: Internet Explorer 6 for Windows XP Service Pack 3 (+ 14 variants)
	"2482017": {"CVE-2011-0038"},
	// MS11-021: Microsoft Excel 2003 Service Pack 3 (+ 3 variants)
	"2489279": {"CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0978", "CVE-2011-0980"},
	// MS11-022: Microsoft PowerPoint 2002 Service Pack 3 (+ 4 variants)
	"2489283": {"CVE-2011-0655", "CVE-2011-0976"},
	// MS11-074: Microsoft Windows SharePoint Services 3.0 Service Pack 2 (32-bit versions) (+ 1 variant)
	"2493987": {"CVE-2011-0653", "CVE-2011-1890"},
	// MS11-074: Microsoft Windows SharePoint Services 2.0
	"2494007": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1892"},
	// MS11-018: Internet Explorer 8 for Windows XP Service Pack 3 (+ 11 variants)
	"2497640": {"CVE-2011-0094", "CVE-2011-1245"},
	// MS11-015: Windows XP Media Center Edition 2005 Service Pack 3
	"2502898": {"CVE-2011-0032"},
	// MS11-021: Microsoft Office 2004 for Mac; MS11-023: Microsoft Office 2004 for Mac
	"2505924": {"CVE-2011-0101", "CVE-2011-0107"},
	// MS11-021: Microsoft Office 2008 for Mac; MS11-023: Microsoft Office 2008 for Mac
	"2505927": {"CVE-2011-0101", "CVE-2011-0107", "CVE-2011-0978"},
	// MS11-021: Open XML File Format Converter for Mac; MS11-023: Open XML File Format Converter for Mac
	"2505935": {"CVE-2011-0101", "CVE-2011-0107", "CVE-2011-0978"},
	// MS11-056: Windows Vista Service Pack 1 and Windows Vista Service Pack 2 (+ 8 variants)
	"2507938": {"CVE-2011-1283", "CVE-2011-1870"},
	// MS11-027: Windows Server 2003 Service Pack 2 (+ 11 variants)
	"2508272": {"CVE-2010-0811", "CVE-2010-3973", "CVE-2011-1243"},
	// MS11-074: Microsoft Groove Server 2010 and Microsoft Groove Server 2010 Service Pack 1
	"2508965": {"CVE-2011-0653", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-022: Microsoft PowerPoint Viewer
	"2519984": {"CVE-2011-0976"},
	// MS11-021: Microsoft Office for Mac 2011; MS11-022: Microsoft Office for Mac 2011
	"2525412": {"CVE-2011-0097", "CVE-2011-0098", "CVE-2011-0101", "CVE-2011-0103", "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0976", "CVE-2011-0978", "CVE-2011-0980"},
	// MS11-050: Internet Explorer 6 for Windows XP Service Pack 3 (+ 21 variants)
	"2530548": {"CVE-2011-1246", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258", "CVE-2011-1260", "CVE-2011-1262"},
	// MS11-042: Windows Vista Service Pack 1 and Windows Vista Service Pack 2 (+ 8 variants)
	"2535512": {"CVE-2011-1868"},
	// MS11-045: Microsoft Excel 2003 Service Pack 3 (+ 3 variants)
	"2537146": {"CVE-2011-1272", "CVE-2011-1274", "CVE-2011-1275", "CVE-2011-1276", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"},
	// MS11-036: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2540162": {"CVE-2011-1270"},
	// MS11-045: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2541012": {"CVE-2011-1275", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"},
	// MS11-045: Microsoft Excel Viewer Service Pack 2
	"2541015": {"CVE-2011-1275", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"},
	// MS11-036: Microsoft PowerPoint 2007 Service Pack 2 (+ 3 variants)
	"2545814": {"CVE-2011-1270"},
	// MS11-074: Microsoft Office Groove 2007 Service Pack 2
	"2552997": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-074: Microsoft Office Groove Management Server 2007 Service Pack 2
	"2552998": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-074: Microsoft Office Groove Data Bridge Server 2007 Service Pack 2
	"2552999": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-074: Microsoft Office Forms Server 2007 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2553005": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-072: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2553074": {"CVE-2011-1986"},
	// MS11-072: Microsoft Excel Viewer Service Pack 2
	"2553075": {"CVE-2011-1986"},
	// MS11-072: Microsoft Office 2007 Service Pack 2
	"2553089": {"CVE-2011-1986"},
	// MS11-072: Microsoft Office 2010 and Microsoft Office 2010 Service Pack 1 (32-bit editions) (+ 1 variant)
	"2553091": {"CVE-2011-1986", "CVE-2011-1988", "CVE-2011-1990"},
	// MS11-072: Excel Services installed on Microsoft Office SharePoint Server 2007 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2553093": {"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-1988"},
	// MS15-033: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"2553164": {"CVE-2015-1639", "CVE-2015-1651"},
	// MS15-081: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2553313": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS12-030: Microsoft Office 2010 (32-bit editions) (+ 3 variants)
	"2553371": {"CVE-2012-0143"},
	// MS15-110: Microsoft SharePoint Server 2010 Service Pack 2
	"2553405": {"CVE-2015-6037", "CVE-2015-6039"},
	// MS13-067: Microsoft Business Productivity Servers on Microsoft SharePoint Server 2010 Service Pack 1 (+ 1 variant)
	"2553408": {"CVE-2013-1315", "CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"},
	// MS12-050: Microsoft InfoPath 2010 (32-bit editions) (+ 3 variants)
	"2553431": {"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"},
	// MS16-107: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2553432": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS11-045: Microsoft Office for Mac 2011
	"2555784": {"CVE-2011-1272", "CVE-2011-1274", "CVE-2011-1276", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279"},
	// MS11-045: Microsoft Office 2008 for Mac
	"2555785": {"CVE-2011-1278"},
	// MS11-045: Microsoft Office 2004 for Mac
	"2555786": {"CVE-2011-1277"},
	// MS11-045: Open XML File Format Converter for Mac
	"2555787": {"CVE-2011-1278"},
	// MS11-054: Windows XP Service Pack 3 (+ 13 variants)
	"2555917": {"CVE-2011-1877", "CVE-2011-1886", "CVE-2011-1887", "CVE-2011-1888"},
	// MS11-057: Internet Explorer 6 for Windows XP Service Pack 3 (+ 11 variants)
	"2559049": {"CVE-2011-1257", "CVE-2011-1963"},
	// MS11-060: Microsoft Visio 2010 (32-bit editions) and Microsoft Visio 2010 (32-bit editions) Service Pack 1 (+ 1 variant)
	"2560978": {"CVE-2011-1979"},
	// MS11-058: Windows Server 2003 Service Pack 2 (+ 2 variants)
	"2562485": {"CVE-2011-1966"},
	// MS11-064: Windows Vista Service Pack 2 (+ 4 variants)
	"2563894": {"CVE-2011-1965"},
	// MS11-074: Microsoft SharePoint Workspace 2010 and Microsoft SharePoint Workspace 2010 Service Pack 1 (32-bit editions) (+ 1 variant)
	"2566445": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-074: Microsoft Office Web Apps 2010 and Microsoft Office Web Apps 2010 Service Pack 1
	"2566449": {"CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891", "CVE-2011-1893"},
	// MS11-077: Windows XP Service Pack 3 (+ 4 variants)
	"2567053": {"CVE-2011-2002"},
	// MS11-073: Microsoft Office 2003 Service Pack 3
	"2584052": {"CVE-2011-1982"},
	// MS11-073: Microsoft Office 2010 and Microsoft Office 2010 Service Pack 1 (32-bit editions) (+ 1 variant)
	"2584066": {"CVE-2011-1980"},
	// MS11-081: Internet Explorer 7 for Windows XP Service Pack 3 (+ 33 variants)
	"2586448": {"CVE-2011-1996", "CVE-2011-1997", "CVE-2011-1998", "CVE-2011-1999"},
	// MS11-072: Microsoft Excel 2003 Service Pack 3 (+ 5 variants)
	"2587505": {"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-1988", "CVE-2011-1990"},
	// MS12-050: Microsoft Groove Server 2010 (+ 1 variant)
	"2589325": {"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"},
	// MS12-034: Microsoft Office 2010 (32-bit editions) (+ 3 variants)
	"2589337": {"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"},
	// MS15-116: Microsoft Access 2007 Service Pack 3
	"2596614": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-081: Microsoft Office 2007 Service Pack 3
	"2596650": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS12-050: Microsoft InfoPath 2007 Service Pack 2 (+ 1 variant)
	"2596666": {"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"},
	// MS15-110: Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"2596670": {"CVE-2015-6037", "CVE-2015-6039"},
	// MS15-116: Microsoft Project 2007 Service Pack 3
	"2596770": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS12-030: Microsoft Excel Viewer
	"2596842": {"CVE-2012-0143"},
	// MS11-094: Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2
	"2596843": {"CVE-2011-3396"},
	// MS14-022: Microsoft SharePoint Designer 2007 Service Pack 3 (ewd)
	"2596861": {"CVE-2014-1754", "CVE-2014-1813"},
	// MS11-094: Microsoft PowerPoint Viewer 2007 Service Pack 2
	"2596912": {"CVE-2011-3396"},
	// MS16-070: Microsoft Visio Viewer 2007 Service Pack 3
	"2596915": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS12-030: Microsoft Office Compatibility Pack Service Pack 2 (+ 1 variant)
	"2597162": {"CVE-2012-0143"},
	// MS12-030: Microsoft Office 2007 Service Pack 2 (+ 1 variant)
	"2597969": {"CVE-2012-0143"},
	// MS13-072: Microsoft Office 2007 Service Pack 3 (msptls)
	"2597973": {"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"},
	// MS16-107: Microsoft Office Compatibility Pack Service Pack 3
	"2597974": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS12-050: Microsoft Office Web Apps 2010 (+ 1 variant)
	"2598239": {"CVE-2012-1862", "CVE-2012-1863"},
	// MS15-081: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2598244": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2477"},
	// MS12-034: Microsoft Office 2003 Service Pack 3
	"2598253": {"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"},
	// MS11-072: Microsoft Office 2008 for Mac
	"2598781": {"CVE-2011-1986", "CVE-2011-1990"},
	// MS11-072: Microsoft Office 2004 for Mac
	"2598782": {"CVE-2011-1986", "CVE-2011-1990"},
	// MS11-072: Microsoft Office for Mac 2011
	"2598783": {"CVE-2011-1986", "CVE-2011-1988", "CVE-2011-1990"},
	// MS11-072: Open XML File Format Converter for Mac
	"2598785": {"CVE-2011-1986", "CVE-2011-1990"},
	// MS11-091: Microsoft Publisher 2007 Service Pack 2 and Microsoft Publisher 2007 Service Pack 3
	"2607702": {"CVE-2011-3411"},
	// MS11-099: Internet Explorer 6 for Windows XP Service Pack 3 (+ 33 variants)
	"2618444": {"CVE-2011-1992", "CVE-2011-2019"},
	// MS11-090: Windows Vista Service Pack 2 (+ 8 variants)
	"2618451": {"CVE-2011-3397"},
	// MS12-020: Windows XP Service Pack 3 (+ 9 variants)
	"2621440": {"CVE-2012-0152"},
	// MS12-004: Windows 7 for 32-bit Systems and Windows 7 for 32-bit Systems Service Pack 1 (+ 5 variants)
	"2636391": {"CVE-2012-0003"},
	// MS12-034: Microsoft Silverlight 5 when installed on Mac (+ 2 variants)
	"2636927": {"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0165", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"},
	// MS11-100: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Windows Server 2003 Itanium-based Edition Service Pack 2
	"2638420": {"CVE-2011-3415"},
	// MS11-094: Microsoft PowerPoint 2010 (32-bit editions) (+ 1 variant)
	"2639142": {"CVE-2011-3413"},
	// MS11-094: Microsoft Office 2008 for Mac
	"2644354": {"CVE-2011-3396"},
	// MS12-009: Windows XP Professional x64 Edition Service Pack 2 (+ 7 variants)
	"2645640": {"CVE-2012-0148", "CVE-2012-0149"},
	// MS12-010: Internet Explorer 6 for Windows XP Service Pack 3 (+ 26 variants)
	"2647516": {"CVE-2012-0011", "CVE-2012-0012", "CVE-2012-0155"},
	// MS12-016: Microsoft .NET Framework 4 when installed on Windows XP Service Pack 3 (+ 16 variants)
	"2651026": {"CVE-2012-0015"},
	// MS11-100: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Windows XP Service Pack 3 (+ 7 variants)
	"2656353": {"CVE-2011-3415"},
	// MS11-100: Microsoft .NET Framework 1.1 Service Pack 1 on Windows Server 2003 Service Pack 2
	"2656358": {"CVE-2011-3415"},
	// MS12-030: Microsoft Excel 2003 Service Pack 3 (+ 6 variants)
	"2663830": {"CVE-2012-0143", "CVE-2012-0185"},
	// MS12-011: Microsoft Office SharePoint Server 2010 and Microsoft Office SharePoint Server 2010 Service Pack 1
	"2663841": {"CVE-2012-0017"},
	// MS12-030: Microsoft Office 2008 for Mac
	"2665346": {"CVE-2012-0141", "CVE-2012-0185"},
	// MS12-030: Microsoft Office for Mac 2011
	"2665351": {"CVE-2012-0142", "CVE-2012-0143", "CVE-2012-0185"},
	// MS12-016: Microsoft Silverlight 4 when installed on Mac
	"2668562": {"CVE-2012-0015"},
	// MS12-023: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2675157": {"CVE-2012-0169", "CVE-2012-0170", "CVE-2012-0172"},
	// MS12-076: Microsoft Office Compatibility Pack Service Pack 2 (+ 1 variant)
	"2687311": {"CVE-2012-1887"},
	// MS12-076: Microsoft Excel Viewer
	"2687313": {"CVE-2012-1885", "CVE-2012-1887"},
	// MS12-064: Microsoft Office Compatibility Pack Service Pack 2 (+ 1 variant)
	"2687314": {"CVE-2012-0182"},
	// MS12-064: Microsoft Office Web Apps 2010 Service Pack 1
	"2687401": {"CVE-2012-0182"},
	// MS15-116: Microsoft InfoPath 2007 Service Pack 3
	"2687406": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-081: Microsoft Office 2007 Service Pack 3
	"2687409": {"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS13-024: Microsoft SharePoint Foundation 2010 Service Pack 1
	"2687418": {"CVE-2013-0083"},
	// MS12-064: Microsoft Word Viewer
	"2687485": {"CVE-2012-0182"},
	// MS12-032: Windows Vista Service Pack 2 (+ 4 variants)
	"2688338": {"CVE-2012-0179"},
	// MS12-034: Microsoft Silverlight 4 when installed on Mac (+ 2 variants)
	"2690729": {"CVE-2012-0162", "CVE-2012-0164", "CVE-2012-0165", "CVE-2012-0167", "CVE-2012-0176", "CVE-2012-0180", "CVE-2012-0181", "CVE-2012-1848"},
	// MS12-050: Microsoft Office SharePoint Server 2007 Service Pack 2 (32-bit editions) (+ 9 variants)
	"2695502": {"CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862", "CVE-2012-1863"},
	// MS12-074: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Windows XP Service Pack 3 (+ 8 variants)
	"2698023": {"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 1.1 Service Pack 1 on Windows Server 2003 Service Pack 2
	"2698032": {"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 1.0 Service Pack 3 on Windows XP Tablet PC Edition 2005 Service Pack 3 and Windows XP Media Center Edition 2005 Service Pack 3
	"2698035": {"CVE-2012-1896", "CVE-2012-4776", "CVE-2012-4777"},
	// MS12-037: Internet Explorer 6 for Windows XP Service Pack 3 (+ 24 variants)
	"2699988": {"CVE-2012-1523", "CVE-2012-1858", "CVE-2012-1873", "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1881"},
	// MS12-039: Microsoft Lync 2010 Attendant (32-bit) (+ 1 variant)
	"2702444": {"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1858"},
	// MS12-054: Windows XP Service Pack 3 (+ 21 variants)
	"2705219": {"CVE-2012-1851"},
	// MS12-042: Windows XP Service Pack 3 (+ 1 variant)
	"2707511": {"CVE-2012-0217"},
	// MS12-039: Microsoft Communicator 2007 R2
	"2708980": {"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849"},
	// MS12-041: Windows XP Professional x64 Edition Service Pack 2 (+ 16 variants)
	"2709162": {"CVE-2012-1868"},
	// MS12-042: Windows 7 for x64-based Systems (+ 3 variants)
	"2709715": {"CVE-2012-1515"},
	// MS12-054: Windows XP Service Pack 3 (+ 21 variants)
	"2712808": {"CVE-2012-1850", "CVE-2012-1852", "CVE-2012-1853"},
	// MS12-073: Microsoft FTP Service 7.0 for IIS 7.0 when installed on Windows Vista Service Pack 2 (+ 15 variants)
	"2716513": {"CVE-2012-2531"},
	// MS12-076: Microsoft Excel 2003 Service Pack 3
	"2720184": {"CVE-2012-2543"},
	// MS12-052: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2722913": {"CVE-2012-1526", "CVE-2012-2523"},
	// MS12-074: Microsoft .NET Framework 4 when installed on Windows XP Service Pack 3 (+ 18 variants)
	"2729449": {"CVE-2012-1896", "CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Windows XP Service Pack 3 (+ 4 variants)
	"2729450": {"CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems (+ 4 variants)
	"2729451": {"CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2729452": {"CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2729453": {"CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2729460": {"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4777"},
	// MS12-074: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 2 variants)
	"2729462": {"CVE-2012-1896", "CVE-2012-4777"},
	// MS12-073: Microsoft FTP Service 7.5 for IIS 7.0 when installed on Windows Vista Service Pack 2 (+ 15 variants)
	"2733829": {"CVE-2012-2531", "CVE-2012-2532"},
	// MS12-074: Microsoft .NET Framework 4 when installed on Windows XP Service Pack 3 (+ 18 variants)
	"2737019": {"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"},
	// MS12-074: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2737083": {"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"},
	// MS12-074: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2737084": {"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4776"},
	// MS12-064: Microsoft Word 2003 Service Pack 3 (+ 3 variants)
	"2742319": {"CVE-2012-0182"},
	// MS13-004: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Microsoft Windows XP Service Pack 3 (+ 8 variants)
	"2742597": {"CVE-2013-0003"},
	// MS13-004: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems (+ 4 variants)
	"2742598": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2742599": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 1.1 Service Pack 1 on Microsoft Windows Server 2003 Service Pack 2
	"2742604": {"CVE-2013-0003"},
	// MS13-004: Microsoft .NET Framework 1.0 Service Pack 3 on Windows XP Tablet PC Edition 2005 Service Pack 3 and Windows XP Media Center Edition 2005 Service Pack 3
	"2742607": {"CVE-2013-0003"},
	// MS13-004: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2742613": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2742614": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2742616": {"CVE-2013-0001"},
	// MS12-063: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2744842": {"CVE-2012-1529", "CVE-2012-2546", "CVE-2012-2548", "CVE-2012-2557"},
	// MS12-074: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2756872": {"CVE-2012-1895", "CVE-2012-1896", "CVE-2012-2519", "CVE-2012-4777"},
	// MS13-004: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems (+ 4 variants)
	"2756920": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2756921": {"CVE-2013-0001"},
	// MS13-004: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2756923": {"CVE-2013-0001"},
	// MS13-002: Microsoft XML Core Services 6.0 on Windows XP Service Pack 3 (+ 25 variants)
	"2757638": {"CVE-2013-0006", "CVE-2013-0007"},
	// MS13-002: Microsoft XML Core Services 4.0 when installed on Windows XP Service Pack 3 (+ 26 variants)
	"2758694": {"CVE-2013-0006"},
	// MS13-002: Microsoft XML Core Services 6.0 on Windows Server 2003 Service Pack 2
	"2758696": {"CVE-2013-0006"},
	// MS13-072: Microsoft Office 2007 Service Pack 3 (mso)
	"2760411": {"CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"},
	// MS13-085: Microsoft Office 2007 Service Pack 3
	"2760585": {"CVE-2013-3890"},
	// MS13-073: Microsoft Office Compatibility Pack Service Pack 3
	"2760588": {"CVE-2013-3158"},
	// MS13-067: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"2760589": {"CVE-2013-1330", "CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"},
	// MS13-073: Microsoft Excel Viewer
	"2760590": {"CVE-2013-3158"},
	// MS13-085: Microsoft Office 2007 Service Pack 3
	"2760591": {"CVE-2013-3890"},
	// MS13-067: Excel Services on Microsoft SharePoint Server 2010 Service Pack 1 (+ 1 variant)
	"2760595": {"CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"},
	// MS12-050: Microsoft Windows SharePoint Services 2.0
	"2760604": {"CVE-2012-1858", "CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861", "CVE-2012-1862"},
	// MS13-067: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 1 (+ 1 variant)
	"2760755": {"CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3858"},
	// MS13-072: Microsoft Office Compatibility Pack Service Pack 3
	"2760823": {"CVE-2013-3160", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3856"},
	// MS12-075: Windows XP Professional x64 Edition Service Pack 2 (+ 19 variants)
	"2761226": {"CVE-2012-2530", "CVE-2012-2553"},
	// MS12-077: Internet Explorer 6 for Windows XP Service Pack 3 (+ 30 variants)
	"2761465": {"CVE-2012-4782", "CVE-2012-4787"},
	// MS12-076: Microsoft Office for Mac 2011
	"2764047": {"CVE-2012-1886"},
	// MS12-076: Microsoft Office 2008 for Mac
	"2764048": {"CVE-2012-1886", "CVE-2012-2543"},
	// MS14-023: Microsoft Office 2007 Service Pack 3 (proofing tools) (Simplified Chinese only)
	"2767772": {"CVE-2014-1808"},
	// MS13-016: Windows 8 for 32-bit Systems (+ 4 variants)
	"2778344": {"CVE-2013-1250", "CVE-2013-1251", "CVE-2013-1252", "CVE-2013-1253", "CVE-2013-1254", "CVE-2013-1255", "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259", "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263", "CVE-2013-1264", "CVE-2013-1265", "CVE-2013-1266", "CVE-2013-1267", "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271", "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275", "CVE-2013-1276", "CVE-2013-1277"},
	// MS13-009: Internet Explorer 6 for Windows XP Service Pack 3 (+ 44 variants)
	"2792100": {"CVE-2013-0015", "CVE-2013-0018", "CVE-2013-0019", "CVE-2013-0020", "CVE-2013-0022", "CVE-2013-0023", "CVE-2013-0024", "CVE-2013-0025", "CVE-2013-0026", "CVE-2013-0028", "CVE-2013-0029"},
	// MS13-040: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2804576": {"CVE-2013-1337"},
	// MS13-040: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2804577": {"CVE-2013-1337"},
	// MS13-040: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2804579": {"CVE-2013-1337"},
	// MS13-040: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2804580": {"CVE-2013-1337"},
	// MS13-040: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2804584": {"CVE-2013-1337"},
	// MS13-036: Windows XP Service Pack 3 (+ 9 variants)
	"2808735": {"CVE-2013-1291", "CVE-2013-1292", "CVE-2013-1293"},
	// MS13-021: Internet Explorer 6 for Windows XP Service Pack 3 (+ 28 variants)
	"2809289": {"CVE-2013-0091", "CVE-2013-1288"},
	// MS14-022: Microsoft SharePoint Designer 2010 Service Pack 1 (32-bit versions) (+ 3 variants)
	"2810069": {"CVE-2014-1754", "CVE-2014-1813"},
	// MS13-031: Windows XP Service Pack 3 (+ 21 variants)
	"2813170": {"CVE-2013-1284"},
	// MS13-072: Microsoft Office 2003 Service Pack 3 (mso)
	"2817474": {"CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"},
	// MS15-116: Microsoft Publisher 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2817478": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS13-085: Microsoft Office 2013 (32-bit editions) (+ 2 variants)
	"2817623": {"CVE-2013-3890"},
	// MS13-072: Microsoft Word Viewer
	"2817683": {"CVE-2013-3853", "CVE-2013-3854"},
	// MS13-086: Microsoft Word 2003 Service Pack 3
	"2826020": {"CVE-2013-3892"},
	// MS13-085: Microsoft Office 2010 Service Pack 1 (32-bit editions) (+ 3 variants)
	"2826023": {"CVE-2013-3890"},
	// MS13-085: Microsoft Excel 2010 Service Pack 1 (32-bit editions) (+ 3 variants)
	"2826033": {"CVE-2013-3890"},
	// MS13-085: Microsoft Office 2010 Service Pack 1 (32-bit editions) (+ 3 variants)
	"2826035": {"CVE-2013-3890"},
	// MS13-085: Microsoft Excel 2013 (32-bit editions) (+ 2 variants)
	"2827238": {"CVE-2013-3890"},
	// MS13-086: Microsoft Office Compatibility Pack Service Pack 3
	"2827329": {"CVE-2013-3891"},
	// MS13-086: Microsoft Word 2007 Service Pack 3
	"2827330": {"CVE-2013-3891"},
	// MS13-046: Windows XP Service Pack 3 (Win32k.sys) (+ 21 variants)
	"2829361": {"CVE-2013-1332"},
	// MS13-037: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2829530": {"CVE-2013-0811", "CVE-2013-1297", "CVE-2013-1306", "CVE-2013-1307", "CVE-2013-1310", "CVE-2013-1311", "CVE-2013-1312", "CVE-2013-3140"},
	// MS13-046: Windows Vista Service Pack 2 (dxgkrnl.sys) (+ 16 variants)
	"2830290": {"CVE-2013-1333", "CVE-2013-1334"},
	// MS13-042: Microsoft Publisher 2007 Service Pack 3 (+ 2 variants)
	"2830397": {"CVE-2013-1316", "CVE-2013-1317", "CVE-2013-1318", "CVE-2013-1319", "CVE-2013-1320", "CVE-2013-1321", "CVE-2013-1322", "CVE-2013-1323", "CVE-2013-1327", "CVE-2013-1329"},
	// MS13-052: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 7 variants)
	"2832407": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 3 variants)
	"2832411": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 3 variants)
	"2832412": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 2 variants)
	"2832414": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 2 variants)
	"2832418": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2833940": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 1.1 Service Pack 1 when installed on Microsoft Windows XP Service Pack 3 (+ 8 variants)
	"2833941": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2833946": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2833947": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 1.1 Service Pack 1 on Microsoft Windows Server 2003 Service Pack 2
	"2833949": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 1.0 Service Pack 3 on Windows XP Tablet PC Edition 2005 Service Pack 3 and Windows XP Media Center Edition 2005 Service Pack 3
	"2833951": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2833957": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2833958": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2833959": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-067: Microsoft SharePoint Portal Server 2003 Service Pack 3 (+ 12 variants)
	"2834052": {"CVE-2013-1315", "CVE-2013-1330", "CVE-2013-3179", "CVE-2013-3180", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3857", "CVE-2013-3858"},
	// MS13-052: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2835393": {"CVE-2013-3129", "CVE-2013-3171", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 3 variants)
	"2835622": {"CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171", "CVE-2013-3178"},
	// MS14-022: Microsoft SharePoint Server 2010 Service Pack 1 (coreserver) (+ 1 variant)
	"2837598": {"CVE-2014-1754", "CVE-2014-1813"},
	// MS15-081: Microsoft Office 2007 Service Pack 3
	"2837610": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469"},
	// MS15-070: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"2837612": {"CVE-2015-2375", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS13-047: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2838727": {"CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117", "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125", "CVE-2013-3126", "CVE-2013-3141"},
	// MS13-052: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2840628": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5 Service Pack 1 when installed on Windows XP Service Pack 3 (+ 8 variants)
	"2840629": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2840631": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2840632": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2840633": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2840642": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2844285": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2844286": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2844287": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-052: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2844289": {"CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3178"},
	// MS13-072: Microsoft Word 2010 Service Pack 1 (32-bit editions) (+ 5 variants)
	"2845537": {"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3858"},
	// MS13-055: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2846071": {"CVE-2013-3115", "CVE-2013-3143", "CVE-2013-3144", "CVE-2013-3145", "CVE-2013-3146", "CVE-2013-3147", "CVE-2013-3149", "CVE-2013-3150", "CVE-2013-3151", "CVE-2013-3152", "CVE-2013-3161", "CVE-2013-3162", "CVE-2013-3163", "CVE-2013-3164", "CVE-2013-3846"},
	// MS13-081: Windows XP Service Pack 3 (+ 21 variants)
	"2847311": {"CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-052: Microsoft Silverlight 5 when installed on Mac (+ 7 variants)
	"2847559": {"CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171"},
	// MS13-053: Windows 8 for 32-bit Systems (win32k.sys) (+ 4 variants)
	"2850851": {"CVE-2013-3167", "CVE-2013-3172", "CVE-2013-3660"},
	// MS13-081: Windows Vista Service Pack 2 (+ 7 variants)
	"2855844": {"CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-082: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2858302": {"CVE-2013-3128"},
	// MS13-063: Windows XP Service Pack 3 (+ 10 variants)
	"2859537": {"CVE-2013-2556", "CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"},
	// MS13-082: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 7 variants)
	"2861188": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 3.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 3 variants)
	"2861189": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 3.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 3 variants)
	"2861190": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 2 variants)
	"2861191": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 3 variants)
	"2861193": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2861194": {"CVE-2013-3860", "CVE-2013-3861"},
	// MS13-082: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2861208": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 3.5 Service Pack 1 when installed on Windows XP Service Pack 3 (+ 9 variants)
	"2861697": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2861698": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2861702": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2861704": {"CVE-2013-3128"},
	// MS13-081: Windows XP Service Pack 3 (+ 21 variants)
	"2862330": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-081: Windows XP Service Pack 3 (+ 21 variants)
	"2862335": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-059: Internet Explorer 6 for Windows XP Service Pack 3 (+ 33 variants)
	"2862772": {"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3193", "CVE-2013-3194"},
	// MS13-082: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2863239": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2863240": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2863243": {"CVE-2013-3128"},
	// MS13-082: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2863253": {"CVE-2013-3128"},
	// MS13-081: Windows 8 for 32-bit Systems (+ 4 variants)
	"2863725": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS15-059: Microsoft Office 2007 Service Pack 3 (file format converters)
	"2863812": {"CVE-2015-1770"},
	// MS15-059: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2863817": {"CVE-2015-1759", "CVE-2015-1770"},
	// MS14-022: Microsoft SharePoint Server 2013 (coreserverloc)
	"2863829": {"CVE-2014-1813"},
	// MS14-022: Microsoft SharePoint Designer 2013 (64-bit versions) (spd)
	"2863836": {"CVE-2014-1754", "CVE-2014-1813"},
	// MS14-022: SharePoint Server 2013 Client Components SDK (32-bit version) (+ 1 variant)
	"2863854": {"CVE-2014-1813"},
	// MS14-001: Microsoft Word Viewer
	"2863867": {"CVE-2014-0259"},
	// MS14-017: Word Automation Services on Microsoft SharePoint Server 2013 (+ 1 variant)
	"2863907": {"CVE-2014-1757", "CVE-2014-1758"},
	// MS13-081: Windows Vista Service Pack 2 (+ 16 variants)
	"2864202": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-081: Windows XP Service Pack 3 (+ 17 variants)
	"2868038": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-069: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2870699": {"CVE-2013-3201", "CVE-2013-3202", "CVE-2013-3203", "CVE-2013-3204", "CVE-2013-3205", "CVE-2013-3206", "CVE-2013-3207", "CVE-2013-3208", "CVE-2013-3209", "CVE-2013-3845"},
	// MS13-081: Windows Vista Service Pack 2 (+ 11 variants)
	"2876284": {"CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3894"},
	// MS13-076: Windows Server 2012 (+ 2 variants)
	"2876315": {"CVE-2013-1341"},
	// MS13-073: Microsoft Office for Mac 2011
	"2877813": {"CVE-2013-3158", "CVE-2013-3159"},
	// MS14-017: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 1 (+ 1 variant)
	"2878220": {"CVE-2014-1757", "CVE-2014-1758"},
	// MS15-116: Microsoft InfoPath 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2878230": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS14-017: Microsoft Office Compatibility Pack Service Pack 3
	"2878236": {"CVE-2014-1758"},
	// MS14-023: Microsoft Office 2010 Service Pack 1 (32-bit editions) (proofing tools) (Simplified Chinese only) (+ 3 variants)
	"2878284": {"CVE-2014-1808"},
	// MS14-017: Microsoft Word Viewer
	"2878304": {"CVE-2014-1757", "CVE-2014-1758"},
	// MS14-023: Microsoft Office 2013 (32-bit editions) (mso) (+ 5 variants)
	"2878316": {"CVE-2014-1756"},
	// MS13-080: Internet Explorer 6 for Windows XP Service Pack 3 (+ 40 variants)
	"2879017": {"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"},
	// MS14-023: Microsoft Office 2013 (32-bit editions) (proofing tools) (+ 5 variants)
	"2880463": {"CVE-2014-1808"},
	// MS15-116: Microsoft Publisher 2007 Service Pack 3
	"2880506": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS16-004: Microsoft Office 2010 Service Pack 2 (32-bit editions)
	"2881029": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Office 2007 Service Pack 3
	"2881067": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS15-022: Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"2881068": {"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS15-044: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2881073": {"CVE-2015-1670"},
	// MS15-044: Microsoft Office 2007 Service Pack 3
	"2883029": {"CVE-2015-1670"},
	// MS16-148: Microsoft Office 2007 Service Pack 3
	"2883033": {"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS14-081: Word Automation Services on Microsoft SharePoint Server 2013 (+ 1 variant)
	"2883050": {"CVE-2014-6356"},
	// MS13-081: Windows XP Service Pack 3 (+ 20 variants)
	"2883150": {"CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3888"},
	// MS13-080: Internet Explorer 11 for Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2884101": {"CVE-2013-3872", "CVE-2013-3873", "CVE-2013-3874", "CVE-2013-3875", "CVE-2013-3882", "CVE-2013-3885", "CVE-2013-3886"},
	// MS13-081: Windows XP Service Pack 3 (+ 16 variants)
	"2884256": {"CVE-2013-3128", "CVE-2013-3879", "CVE-2013-3880", "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894"},
	// MS13-084: Microsoft Windows SharePoint Services 3.0 Service Pack 3 (32-bit versions) (+ 8 variants)
	"2885089": {"CVE-2013-3889", "CVE-2013-3895"},
	// MS13-091: Microsoft Office 2010 Service Pack 1 (32-bit editions) (+ 6 variants)
	"2885093": {"CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325"},
	// MS13-101: Windows Vista Service Pack 2 (+ 11 variants)
	"2887069": {"CVE-2013-3899", "CVE-2013-3902", "CVE-2013-3903", "CVE-2013-5058"},
	// MS13-088: Internet Explorer 6 for Windows XP Service Pack 3 (+ 44 variants)
	"2888505": {"CVE-2013-3871", "CVE-2013-3908", "CVE-2013-3909", "CVE-2013-3910", "CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3916"},
	// MS13-085: Microsoft Office for Mac 2011
	"2889496": {"CVE-2013-3890"},
	// MS16-148: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2889841": {"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS15-116: Microsoft OneNote 2007 Service Pack 3
	"2889915": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS13-101: Windows XP Service Pack 3 (+ 26 variants)
	"2893984": {"CVE-2013-3907"},
	// MS13-097: Internet Explorer 6 for Windows XP Service Pack 3 (+ 47 variants)
	"2898785": {"CVE-2013-5045", "CVE-2013-5046", "CVE-2013-5049", "CVE-2013-5051", "CVE-2013-5052"},
	// MS14-009: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2898855": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2898856": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2898857": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2898858": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 1.1 Service Pack 1 on Microsoft Windows Server 2003 Service Pack 2
	"2898860": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2898864": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2898865": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2898866": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2898868": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2898869": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 when installed on Windows 8 for 32-bit Systems (+ 4 variants)
	"2898870": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"2898871": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS15-116: Microsoft Office 2007 IME (Japanese) Service Pack 3
	"2899473": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Pinyin IME 2010 (32-bit version) (+ 1 variant)
	"2899516": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS14-081: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2899518": {"CVE-2014-6356"},
	// MS14-081: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"2899581": {"CVE-2014-6356"},
	// MS14-009: Microsoft .NET Framework 4 when installed on Microsoft Windows XP Service Pack 3 (+ 14 variants)
	"2901110": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows XP Service Pack 3 (+ 4 variants)
	"2901111": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2901112": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2901113": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 1.1 Service Pack 1 on Microsoft Windows Server 2003 Service Pack 2
	"2901115": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2901118": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2901119": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2901120": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2901125": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2901126": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 when installed on Windows 8 for 32-bit Systems (+ 4 variants)
	"2901127": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS14-009: Microsoft .NET Framework 4.5.1 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"2901128": {"CVE-2014-0257", "CVE-2014-0295"},
	// MS13-105: Microsoft Exchange Server 2007 Service Pack 3
	"2903911": {"CVE-2013-5072"},
	// MS14-009: Microsoft .NET Framework 1.0 Service Pack 3 on Windows XP Tablet PC Edition 2005 Service Pack 3 and Windows XP Media Center Edition 2005 Service Pack 3
	"2904878": {"CVE-2014-0253", "CVE-2014-0295"},
	// MS15-116: Microsoft Access 2016 (32-bit edition) (+ 1 variant)
	"2910978": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS14-009: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2911501": {"CVE-2014-0253", "CVE-2014-0257"},
	// MS14-009: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2911502": {"CVE-2014-0253", "CVE-2014-0257"},
	// MS14-001: Microsoft Word 2003 Service Pack 3 (+ 7 variants)
	"2916605": {"CVE-2014-0258", "CVE-2014-0259"},
	// MS15-116: Microsoft Publisher 2016 (32-bit edition) (+ 1 variant)
	"2920680": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-081: Microsoft Word 2016 (32-bit editions) (+ 1 variant)
	"2920691": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-099: Microsoft Excel 2016 (32-bit editions) (+ 1 variant); MS15-110: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"2920693": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2545", "CVE-2015-2557"},
	// MS15-116: Microsoft Project 2016 (32-bit edition) (+ 1 variant)
	"2920698": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-081: Microsoft Visio 2016 (32-bit editions) (+ 1 variant)
	"2920708": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-116: Microsoft OneNote 2016 (32-bit edition) (+ 1 variant)
	"2920726": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS16-004: Microsoft Office 2016 (32-bit edition)
	"2920727": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS14-081: Microsoft Word Viewer
	"2920729": {"CVE-2014-6356"},
	// MS15-012: Microsoft Excel 2013 (32-bit editions) (+ 5 variants)
	"2920753": {"CVE-2015-0064", "CVE-2015-0065"},
	// MS15-012: Microsoft Excel 2007 Service Pack 3
	"2920788": {"CVE-2015-0064", "CVE-2015-0065"},
	// MS14-083: Microsoft Excel Viewer; MS15-012: Microsoft Excel Viewer
	"2920791": {"CVE-2014-6361", "CVE-2015-0064", "CVE-2015-0065"},
	// MS15-012: Word Automation Services
	"2920810": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS14-017: Microsoft Office for Mac 2011
	"2939132": {"CVE-2014-1757", "CVE-2014-1758"},
	// MS14-017: Microsoft Word 2003 Service Pack 3 (+ 15 variants)
	"2949660": {"CVE-2014-1757", "CVE-2014-1758"},
	// MS14-022: Microsoft Windows SharePoint Services 3.0 Service Pack 3 (32-bit versions) (+ 21 variants)
	"2952166": {"CVE-2014-1754", "CVE-2014-1813"},
	// MS15-012: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2956058": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS16-029: Microsoft Office 2010 Service Pack 2 (32-bit editions)
	"2956063": {"CVE-2016-0021", "CVE-2016-0134"},
	// MS15-012: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2956066": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS15-012: Microsoft Web Applications 2010 Service Pack 2
	"2956070": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS15-012: Microsoft Office 2010 Service Pack 2 (32-bit editions) (proofing tools) (+ 1 variant)
	"2956073": {"CVE-2015-0064", "CVE-2015-0065"},
	// MS15-012: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2956081": {"CVE-2015-0064", "CVE-2015-0065"},
	// MS15-012: Microsoft Word Viewer
	"2956092": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS15-012: Microsoft Office Compatibility Pack Service Pack 3
	"2956097": {"CVE-2015-0064", "CVE-2015-0065"},
	// MS15-012: Microsoft Office Compatibility Pack Service Pack 3
	"2956098": {"CVE-2015-0063", "CVE-2015-0065"},
	// MS15-012: Microsoft Word 2007 Service Pack 3
	"2956099": {"CVE-2015-0063"},
	// MS16-029: Microsoft Office 2007 Service Pack 3
	"2956110": {"CVE-2016-0021", "CVE-2016-0134"},
	// MS15-022: Microsoft Office 2013 (32-bit editions) (+ 5 variants)
	"2956151": {"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS15-022: Microsoft Word Viewer
	"2956188": {"CVE-2015-0085", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS15-022: Microsoft Excel Viewer
	"2956189": {"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS14-028: Windows Server 2012 R2 (+ 1 variant)
	"2962073": {"CVE-2014-0256"},
	// MS15-070: Microsoft Office Compatibility Pack Service Pack 3
	"2965208": {"CVE-2015-2375", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2424"},
	// MS15-070: Microsoft Excel Viewer 2007 Service Pack 3
	"2965209": {"CVE-2015-2375", "CVE-2015-2377", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS15-033: Microsoft Office Compatibility Pack Service Pack 3
	"2965210": {"CVE-2015-1639"},
	// MS15-033: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"2965215": {"CVE-2015-1639", "CVE-2015-1649", "CVE-2015-1651"},
	// MS15-036: Microsoft SharePoint Server 2013 Service Pack 1
	"2965219": {"CVE-2015-1640"},
	// MS15-033: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2965236": {"CVE-2015-1639", "CVE-2015-1651"},
	// MS15-081: Microsoft Visio 2007 Service Pack 3
	"2965280": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-070: Microsoft PowerPoint 2007 Service Pack 3
	"2965283": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"},
	// MS15-033: Microsoft Word Viewer
	"2965289": {"CVE-2015-1639", "CVE-2015-1641"},
	// MS15-081: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2965310": {"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-116: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"2965313": {"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS14-057: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2968292": {"CVE-2014-4073", "CVE-2014-4121"},
	// MS14-057: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2968294": {"CVE-2014-4073", "CVE-2014-4121"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2968295": {"CVE-2014-4073", "CVE-2014-4121"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2968296": {"CVE-2014-4073", "CVE-2014-4121"},
	// MS14-057: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2972098": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2972100": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2972101": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2972103": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows Server 2003 Service Pack 2 (+ 2 variants)
	"2972105": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4 when installed on Windows Server 2003 Service Pack 2 (+ 12 variants)
	"2972106": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4.5/4.5.1/4.5.2 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2972107": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS15-046: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"2975808": {"CVE-2015-1683"},
	// MS14-044: Microsoft SQL Server 2014 for x64-based Systems
	"2977315": {"CVE-2014-4061"},
	// MS14-044: Microsoft SQL Server 2008 R2 for 32-bit Systems Service Pack 2 (+ 2 variants)
	"2977320": {"CVE-2014-1820"},
	// MS14-044: Microsoft SQL Server 2008 for 32-bit Systems Service Pack 3 (+ 2 variants)
	"2977321": {"CVE-2014-1820"},
	// MS14-044: Microsoft SQL Server 2012 for 32-bit Systems Service Pack 1
	"2977326": {"CVE-2014-1820"},
	// MS14-057: Microsoft .NET Framework 4.5.1/4.5.2 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"2978041": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4.5/4.5.1/4.5.2 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2978042": {"CVE-2014-4073", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"2979568": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"2979570": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"2979571": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"2979573": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows Server 2003 Service Pack 2 (+ 2 variants)
	"2979574": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4 when installed on Windows Server 2003 Service Pack 2 (+ 12 variants)
	"2979575": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4.5.1/4.5.2 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"2979576": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4.5/4.5.1/4.5.2 on Windows 8 for 32-bit Systems (+ 4 variants)
	"2979577": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-057: Microsoft .NET Framework 4.5/4.5.1/4.5.2 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"2979578": {"CVE-2014-4121", "CVE-2014-4122"},
	// MS14-055: Microsoft Lync Server 2010 (Response Group Service)
	"2982388": {"CVE-2014-4070", "CVE-2014-4071"},
	// MS14-055: Microsoft Lync Server 2013 (Response Group Service)
	"2982389": {"CVE-2014-4070", "CVE-2014-4071"},
	// MS14-055: Microsoft Lync Server 2013 (Web Components Server)
	"2982390": {"CVE-2014-4068", "CVE-2014-4071"},
	// MS16-054: Microsoft Office 2007 Service Pack 3
	"2984938": {"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"},
	// MS15-022: Microsoft Office 2007 Service Pack 3
	"2984939": {"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS16-054: Microsoft Office 2007 Service Pack 3
	"2984943": {"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"},
	// MS14-055: Microsoft Lync Server 2013 (Server)
	"2986072": {"CVE-2014-4068", "CVE-2014-4070"},
	// MS16-133: Microsoft Office 2007 Service Pack 3
	"2986253": {"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"},
	// MS15-081: Microsoft Office Compatibility Pack Service Pack 3
	"2986254": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS14-075: Microsoft Exchange Server 2010 Service Pack 3
	"2986475": {"CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"},
	// MS14-055: Microsoft Lync Server 2013 (Core Components)
	"2992965": {"CVE-2014-4070", "CVE-2014-4071"},
	// MS14-045: Windows Server 2003 Service Pack 2 (+ 2 variants)
	"2993651": {"CVE-2014-4064"},
	// MS14-075: Microsoft Exchange Server 2007 Service Pack 3
	"2996150": {"CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"},
	// MS16-070: Microsoft Visio Viewer 2010 (32-bit Edition) (+ 1 variant)
	"2999465": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS14-064: Windows Server 2003 Service Pack 2 (+ 2 variants)
	"3006226": {"CVE-2014-6352"},
	// MS14-081: Microsoft Word 2007 Service Pack 3 (+ 11 variants)
	"3017301": {"CVE-2014-6356", "CVE-2014-6357"},
	// MS14-083: Microsoft Excel 2013 (32-bit editions) (+ 5 variants)
	"3017347": {"CVE-2014-6360"},
	// MS14-081: Microsoft Office for Mac 2011
	"3018888": {"CVE-2014-6356"},
	// MS15-048: Microsoft .NET Framework 1.1 Service Pack 1 on Microsoft Windows Server 2003 Service Pack 2
	"3023211": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"3023213": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3023215": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"3023217": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3023219": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows Server 2003 Service Pack 2 (+ 2 variants)
	"3023220": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 4 when installed on Windows Server 2003 Service Pack 2 (+ 12 variants)
	"3023221": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 4.5.1/4.5.2 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"3023222": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 4.5/4.5.1/4.5.2 on Windows 8 for 32-bit Systems (+ 4 variants)
	"3023223": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 4.5/4.5.1/4.5.2 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"3023224": {"CVE-2015-1672"},
	// MS15-048: Microsoft .NET Framework 3.5.1 on Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3032655": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 4 when installed on Windows Server 2003 Service Pack 2 (+ 12 variants)
	"3032662": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 4.5.1/4.5.2 on Windows 8.1 for 32-bit Systems (+ 4 variants)
	"3032663": {"CVE-2015-1673"},
	// MS15-020: Windows Server 2003 Service Pack 2 (+ 19 variants)
	"3033889": {"CVE-2015-0096"},
	// MS15-048: Microsoft .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 (+ 4 variants)
	"3035485": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems (+ 3 variants)
	"3035486": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 3.5 on Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3035487": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 2.0 Service Pack 2 when installed on Microsoft Windows Server 2003 Service Pack 2 (+ 2 variants)
	"3035488": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 4.5/4.5.1/4.5.2 on Windows 8 for 32-bit Systems (+ 4 variants)
	"3035489": {"CVE-2015-1673"},
	// MS15-048: Microsoft .NET Framework 4.5/4.5.1/4.5.2 when installed on Windows Vista Service Pack 2 (+ 7 variants)
	"3035490": {"CVE-2015-1673"},
	// MS15-025: Windows Server 2003 Service Pack 2 (3033395-v2) (+ 2 variants)
	"3038680": {"CVE-2015-0073"},
	// MS15-022: Microsoft Excel 2007 Service Pack 3 (+ 32 variants)
	"3038999": {"CVE-2015-0086", "CVE-2015-0097", "CVE-2015-1633", "CVE-2015-1636"},
	// MS15-020: Windows Server 2003 Service Pack 2 (+ 24 variants)
	"3039066": {"CVE-2015-0081"},
	// MS15-081: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3039734": {"CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-046: Microsoft SharePoint Server 2013 Service Pack 1
	"3039736": {"CVE-2015-1683"},
	// MS16-029: Microsoft Office 2013 Service Pack 1 (32-bit editions)
	"3039746": {"CVE-2016-0021", "CVE-2016-0134"},
	// MS15-046: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3039748": {"CVE-2015-1683"},
	// MS16-015: Microsoft SharePoint Server 2013 Service Pack 1
	"3039768": {"CVE-2016-0039"},
	// MS15-044: Microsoft Lync 2013 Service Pack 1 (32-bit) (Skype for Business) (+ 3 variants)
	"3039779": {"CVE-2015-1670"},
	// MS16-004: Microsoft Office 2013 Service Pack 1 (32-bit editions)
	"3039794": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS15-081: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3039798": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-038: Windows Server 2003 Service Pack 2 (+ 1 variant)
	"3045999": {"CVE-2015-1643"},
	// MS15-068: Windows Server 2008 for x64-based Systems Service Pack 2 (+ 6 variants)
	"3046339": {"CVE-2015-2361"},
	// MS15-033: Microsoft Word 2007 Service Pack 3 (+ 8 variants)
	"3048019": {"CVE-2015-1639", "CVE-2015-1649", "CVE-2015-1650", "CVE-2015-1651"},
	// MS15-046: Microsoft Office for Mac 2011
	"3048688": {"CVE-2015-1683"},
	// MS15-038: Microsoft Windows Server 2003 for Itanium-based Systems Service Pack 2
	"3049576": {"CVE-2015-1643"},
	// MS15-053: JScript 5.8 and VBScript 5.8 on Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
	"3050941": {"CVE-2015-1684"},
	// MS15-053: JScript 5.7 and VBScript 5.7 on Windows Server 2003 Service Pack 2 (+ 8 variants)
	"3050945": {"CVE-2015-1684"},
	// MS15-053: JScript 5.6 and VBScript 5.6 on Windows Server 2003 Service Pack 2 (+ 1 variant)
	"3050946": {"CVE-2015-1684"},
	// MS15-044: Microsoft Lync 2010 (32-bit) (+ 1 variant)
	"3051464": {"CVE-2015-1670"},
	// MS15-044: Microsoft Lync 2010 Attendee[1] (user level install)
	"3051465": {"CVE-2015-1670"},
	// MS15-044: Microsoft Lync 2010 Attendee (admin level install)
	"3051466": {"CVE-2015-1670"},
	// MS15-044: Microsoft Live Meeting 2007 Console[1]
	"3051467": {"CVE-2015-1670"},
	// MS15-033: Microsoft Office for Mac 2011
	"3051737": {"CVE-2015-1641", "CVE-2015-1649", "CVE-2015-1650", "CVE-2015-1651"},
	// MS15-036: Microsoft Project Server 2010 Service Pack 2 (+ 2 variants)
	"3052044": {"CVE-2015-1640", "CVE-2015-1653"},
	// MS15-116: Microsoft InfoPath 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3054793": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-081: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3054816": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2477"},
	// MS15-046: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3054833": {"CVE-2015-1683"},
	// MS15-046: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3054839": {"CVE-2015-1683"},
	// MS15-046: Microsoft PowerPoint Viewer
	"3054840": {"CVE-2015-1683"},
	// MS15-046: Microsoft Office Web Apps 2010 Service Pack 2
	"3054843": {"CVE-2015-1683"},
	// MS15-081: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3054858": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-070: Excel Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3054861": {"CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS16-107: Microsoft SharePoint Server 2013 Service Pack 1
	"3054862": {"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"},
	// MS15-081: Microsoft Visio 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3054876": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Office 2007 Service Pack 3
	"3054888": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Visio 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3054929": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-070: Microsoft Word Viewer
	"3054958": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS15-081: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3054960": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-070: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3054963": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"},
	// MS15-070: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3054968": {"CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS16-107: Microsoft PowerPoint Viewer
	"3054969": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS15-070: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3054971": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2415", "CVE-2015-2424"},
	// MS15-081: Microsoft Word Web Apps 2010 Service Pack 2
	"3054974": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-116: Microsoft OneNote 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3054978": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS16-054: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3054984": {"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"},
	// MS15-081: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3054991": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Excel 2007 Service Pack 3
	"3054992": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-099: Microsoft Office Compatibility Pack Service Pack 3
	"3054993": {"CVE-2015-2545"},
	// MS15-110: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"3054994": {"CVE-2015-2555", "CVE-2015-6037"},
	// MS15-099: Microsoft Excel Viewer
	"3054995": {"CVE-2015-2545"},
	// MS15-070: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3054999": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415"},
	// MS15-081: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3055003": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3055029": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3055030": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3055033": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3055037": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3055039": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3055044": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft PowerPoint 2007 Service Pack 3
	"3055051": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Word 2007 Service Pack 3
	"3055052": {"CVE-2015-1642", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Word Viewer
	"3055053": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-081: Microsoft Word Viewer
	"3055054": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469"},
	// MS15-033: Microsoft Outlook for Mac for Office 365
	"3055707": {"CVE-2015-1639", "CVE-2015-1641", "CVE-2015-1649", "CVE-2015-1650", "CVE-2015-1651"},
	// MS15-044: Microsoft Silverlight 5 when installed on Mac (+ 5 variants)
	"3056819": {"CVE-2015-1670"},
	// MS15-046: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 19 variants)
	"3057181": {"CVE-2015-1683"},
	// MS15-053: VBScript 5.6 on Windows Server 2003 Service Pack 2 (+ 14 variants)
	"3057263": {"CVE-2015-1684", "CVE-2015-1686"},
	// MS15-104: Skype for Business Server 2015
	"3061064": {"CVE-2015-2532"},
	// MS15-069: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3061512": {"CVE-2015-2369"},
	// MS15-069: Windows Server 2003 Service Pack 2 (+ 10 variants)
	"3067903": {"CVE-2015-2368"},
	// MS15-069: Windows 7 for 32-bit Systems Service Pack 1 (+ 2 variants)
	"3070738": {"CVE-2015-2369"},
	// MS15-070: Microsoft Excel 2007 Service Pack 3 (+ 13 variants)
	"3072620": {"CVE-2015-2375", "CVE-2015-2376", "CVE-2015-2377", "CVE-2015-2378", "CVE-2015-2379", "CVE-2015-2380", "CVE-2015-2415", "CVE-2015-2424"},
	// MS15-082: Windows Vista Service Pack 2 (+ 21 variants)
	"3075220": {"CVE-2015-2473"},
	// MS15-082: Windows Vista Service Pack 2 (+ 1 variant)
	"3075221": {"CVE-2015-2473"},
	// MS15-080: Windows 10 for 64-bit Systems
	"3078662": {"CVE-2015-2460", "CVE-2015-2463", "CVE-2015-2464"},
	// MS15-109: Windows Server 2008 for 32-bit Systems Service Pack 2 (+ 17 variants)
	"3080446": {"CVE-2015-2548"},
	// MS15-081: Microsoft Office for Mac 2011
	"3081349": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467"},
	// MS15-080: Windows 10 for 32-bit Systems (+ 1 variant)
	"3081436": {"CVE-2015-2432", "CVE-2015-2453", "CVE-2015-2454", "CVE-2015-2460", "CVE-2015-2463", "CVE-2015-2464"},
	// MS15-097: Windows 10 for 32-bit Systems (+ 1 variant); MS15-102: Windows 10 for 32-bit Systems (+ 1 variant)
	"3081455": {"CVE-2015-2510", "CVE-2015-2525"},
	// MS15-102: Windows 8 for 32-bit Systems (+ 9 variants)
	"3082089": {"CVE-2015-2525"},
	// MS15-081: Microsoft Office for Mac 2016
	"3082420": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467", "CVE-2015-2469", "CVE-2015-2470"},
	// MS15-102: Windows Vista Service Pack 2 (+ 21 variants)
	"3084135": {"CVE-2015-2524", "CVE-2015-2528"},
	// MS15-116: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3085477": {"CVE-2015-6038", "CVE-2015-6094"},
	// MS15-099: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3085502": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2545"},
	// MS15-116: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3085511": {"CVE-2015-6038", "CVE-2015-6094"},
	// MS15-110: Microsoft Visio 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085514": {"CVE-2015-2555", "CVE-2015-2558"},
	// MS15-110: Microsoft Office Web Apps 2010 Service Pack 2
	"3085520": {"CVE-2015-2555", "CVE-2015-2558"},
	// MS15-099: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085526": {"CVE-2015-2545"},
	// MS15-131: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085528": {"CVE-2015-6040", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"},
	// MS15-081: Microsoft Office 2016 (32-bit editions) (+ 1 variant)
	"3085538": {"CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2467", "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477"},
	// MS15-110: Microsoft Visio 2007 Service Pack 3
	"3085542": {"CVE-2015-2555", "CVE-2015-2558"},
	// MS15-099: Microsoft Excel 2007 Service Pack 3
	"3085543": {"CVE-2015-2545"},
	// MS15-046: Microsoft Office 2007 Service Pack 3
	"3085544": {"CVE-2015-1682"},
	// MS15-116: Microsoft PowerPoint 2007 Service Pack 3
	"3085548": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-131: Microsoft Office 2007 Service Pack 3
	"3085549": {"CVE-2015-6040", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"},
	// MS15-116: Microsoft Office Compatibility Pack Service Pack 3
	"3085551": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Word 2007 Service Pack 3
	"3085552": {"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-099: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085560": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"},
	// MS15-116: Microsoft Publisher 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3085561": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-110: Microsoft SharePoint Server 2013 Service Pack 1
	"3085567": {"CVE-2015-2556", "CVE-2015-6037"},
	// MS15-110: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3085571": {"CVE-2015-2555", "CVE-2015-2558"},
	// MS15-099: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3085572": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"},
	// MS15-110: Microsoft SharePoint Foundation 2013 Service Pack 1
	"3085582": {"CVE-2015-2556"},
	// MS15-110: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3085583": {"CVE-2015-2557"},
	// MS15-116: Microsoft Access 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3085584": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085594": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-110: Microsoft Excel Web App 2010 Service Pack 2
	"3085595": {"CVE-2015-2555", "CVE-2015-2558"},
	// MS15-110: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085609": {"CVE-2015-2557"},
	// MS15-116: Microsoft Project 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3085614": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-110: Microsoft Excel 2007 Service Pack 3
	"3085615": {"CVE-2015-2555", "CVE-2015-2557"},
	// MS15-110: Microsoft Office Compatibility Pack Service Pack 3
	"3085618": {"CVE-2015-2555", "CVE-2015-2557"},
	// MS15-110: Microsoft Excel Viewer
	"3085619": {"CVE-2015-2555", "CVE-2015-2557"},
	// MS15-099: Microsoft Office 2007 Service Pack 3
	"3085620": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"},
	// MS15-099: Microsoft Office 2016 (32-bit editions) (+ 1 variant)
	"3085635": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523"},
	// MS15-097: Windows Vista Service Pack 2 (+ 21 variants)
	"3087039": {"CVE-2015-2508", "CVE-2015-2510"},
	// MS15-097: Windows Vista Service Pack 2 (+ 6 variants)
	"3087135": {"CVE-2015-2506", "CVE-2015-2507", "CVE-2015-2508", "CVE-2015-2511", "CVE-2015-2512", "CVE-2015-2517", "CVE-2015-2518", "CVE-2015-2527", "CVE-2015-2529", "CVE-2015-2546"},
	// MS15-099: Microsoft Excel for Mac 2011
	"3088501": {"CVE-2015-2521", "CVE-2015-2545"},
	// MS15-099: Microsoft Excel 2016 for Mac
	"3088502": {"CVE-2015-2521", "CVE-2015-2545"},
	// MS15-101: Windows Vista Service Pack 2 (+ 19 variants)
	"3089662": {"CVE-2015-2526"},
	// MS15-110: Microsoft Excel 2016 for Mac
	"3097264": {"CVE-2015-2557"},
	// MS15-110: Microsoft Excel for Mac 2011
	"3097266": {"CVE-2015-2557"},
	// MS15-109: Windows 10 for 32-bit Systems (+ 1 variant)
	"3097617": {"CVE-2015-2548"},
	// MS15-116: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3101359": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3101360": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Excel Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3101364": {"CVE-2015-6093"},
	// MS15-116: Microsoft Visio 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3101365": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3101367": {"CVE-2015-6038", "CVE-2015-6094"},
	// MS15-116: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3101370": {"CVE-2015-6038", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft OneNote 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3101371": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3101499": {"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"},
	// MS15-116: Microsoft Project 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3101506": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Visio 2016 (32-bit edition) (+ 1 variant)
	"3101507": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft PowerPoint 2016 (32-bit edition) (+ 1 variant)
	"3101509": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3101510": {"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"},
	// MS15-116: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3101512": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3101513": {"CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3101514": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"},
	// MS16-054: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101520": {"CVE-2016-0126", "CVE-2016-0183", "CVE-2016-0198"},
	// MS15-116: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101521": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3101525": {"CVE-2015-6093", "CVE-2015-6094"},
	// MS15-116: Microsoft Visio 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101526": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101529": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-131: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101532": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"},
	// MS15-116: Microsoft Office Web Apps 2010 Service Pack 2
	"3101533": {"CVE-2015-6038", "CVE-2015-6094"},
	// MS15-116: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101543": {"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6123"},
	// MS15-116: Microsoft Access 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3101544": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Visio 2007 Service Pack 3
	"3101553": {"CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Excel 2007 Service Pack 3
	"3101554": {"CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office 2007 Service Pack 3
	"3101555": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Office Compatibility Pack Service Pack 3
	"3101558": {"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"3101559": {"CVE-2015-6093", "CVE-2015-6094"},
	// MS15-116: Microsoft Excel Viewer
	"3101560": {"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Word Viewer
	"3101564": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	// MS15-116: Microsoft Excel for Mac 2011
	"3102924": {"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093"},
	// MS15-116: Microsoft Excel 2016 for Mac
	"3102925": {"CVE-2015-2503", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093"},
	// MS15-118: Windows Vista Service Pack 2 (+ 21 variants)
	"3104507": {"CVE-2015-6099", "CVE-2015-6115"},
	// MS16-007: Windows Vista Service Pack 2 (+ 8 variants)
	"3108664": {"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019"},
	// MS15-128: Windows 7 for 32-bit Systems Service Pack 1 (+ 14 variants); MS15-135: Windows Vista Service Pack 2 (+ 21 variants)
	"3109094": {"CVE-2015-6175"},
	// MS16-007: Windows Vista Service Pack 2 (+ 14 variants)
	"3109560": {"CVE-2016-0014", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"},
	// MS16-007: Windows Vista Service Pack 2 (+ 16 variants)
	"3110329": {"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"},
	// MS16-015: Excel Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3114335": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"},
	// MS16-015: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3114338": {"CVE-2016-0054"},
	// MS16-099: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114340": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"},
	// MS15-131: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114342": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"},
	// MS15-131: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3114382": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6177"},
	// MS16-148: Microsoft Publisher 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114395": {"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-004: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114396": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-099: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114400": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"},
	// MS16-015: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3114401": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"},
	// MS16-004: Microsoft Visio 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114402": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS15-131: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114403": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"},
	// MS16-015: Microsoft Office Web Apps 2010 Service Pack 2
	"3114407": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"},
	// MS16-029: Microsoft InfoPath 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114414": {"CVE-2016-0057", "CVE-2016-0134"},
	// MS15-131: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114415": {"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"},
	// MS16-004: Microsoft Visio 2007 Service Pack 3
	"3114421": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS15-131: Microsoft Excel 2007 Service Pack 3
	"3114422": {"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"},
	// MS16-029: Microsoft InfoPath 2007 Service Pack 3
	"3114426": {"CVE-2016-0057", "CVE-2016-0134"},
	// MS16-004: Microsoft PowerPoint 2007 Service Pack 3
	"3114429": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS15-131: Microsoft Office Compatibility Pack Service Pack 3
	"3114431": {"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"},
	// MS16-015: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"3114432": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"},
	// MS15-131: Microsoft Excel Viewer
	"3114433": {"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172"},
	// MS16-099: Microsoft Office 2007 Service Pack 3
	"3114442": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317"},
	// MS16-099: Microsoft OneNote 2007 Service Pack 3
	"3114456": {"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS15-131: Microsoft Office Compatibility Pack Service Pack 3
	"3114457": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"},
	// MS15-131: Microsoft Word 2007 Service Pack 3
	"3114458": {"CVE-2015-6040", "CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6177"},
	// MS16-015: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3114481": {"CVE-2016-0054"},
	// MS16-004: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114482": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114486": {"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"},
	// MS16-004: Microsoft Visio 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3114489": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114494": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114504": {"CVE-2016-0010"},
	// MS16-004: Microsoft Visio 2016 (32-bit edition) (+ 1 variant)
	"3114511": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft PowerPoint 2016 (32-bit edition) (+ 1 variant)
	"3114518": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3114520": {"CVE-2016-0010"},
	// MS16-004: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3114526": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3114527": {"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"},
	// MS16-004: Microsoft Excel 2007 Service Pack 3
	"3114540": {"CVE-2016-0010"},
	// MS16-004: Microsoft Office 2007 Service Pack 3
	"3114541": {"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"},
	// MS16-004: Microsoft Office Compatibility Pack Service Pack 3
	"3114546": {"CVE-2015-0012", "CVE-2016-0010", "CVE-2016-0012"},
	// MS16-004: Microsoft Excel Viewer
	"3114547": {"CVE-2015-0012", "CVE-2016-0010", "CVE-2016-0012"},
	// MS16-015: Microsoft Office Compatibility Pack Service Pack 3
	"3114548": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-004: Microsoft Word 2007 Service Pack 3
	"3114549": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114553": {"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"},
	// MS16-004: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114554": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114557": {"CVE-2016-0010", "CVE-2016-0035"},
	// MS16-004: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114564": {"CVE-2016-0010"},
	// MS16-004: Microsoft Word Viewer
	"3114569": {"CVE-2015-0012", "CVE-2016-0012", "CVE-2016-0035"},
	// MS16-029: Microsoft Office 2016 (32-bit edition)
	"3114690": {"CVE-2016-0021", "CVE-2016-0134"},
	// MS16-015: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3114698": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-015: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3114702": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-015: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114724": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-015: Microsoft SharePoint Foundation 2013 Service Pack 1
	"3114733": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053"},
	// MS16-015: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114734": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-070: Microsoft Visio 2007 Service Pack 3
	"3114740": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS16-015: Microsoft Excel 2007 Service Pack 3
	"3114741": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-015: Microsoft Office 2007 Service Pack 3
	"3114742": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0054", "CVE-2016-0056"},
	// MS16-107: Microsoft PowerPoint 2007 Service Pack 3
	"3114744": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-015: Microsoft Office Compatibility Pack Service Pack 3
	"3114745": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-015: Microsoft Excel Viewer
	"3114747": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-015: Microsoft Word 2007 Service Pack 3
	"3114748": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-015: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114752": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-015: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114755": {"CVE-2016-0054", "CVE-2016-0055"},
	// MS16-015: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114759": {"CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-015: Microsoft Word Viewer
	"3114773": {"CVE-2016-0054", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-029: Microsoft Word Viewer
	"3114812": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-029: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114824": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-029: Microsoft InfoPath 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3114833": {"CVE-2016-0057", "CVE-2016-0134"},
	// MS16-029: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3114855": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-099: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114869": {"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-042: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3114871": {"CVE-2016-0127"},
	// MS16-070: Microsoft Visio 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114872": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS16-029: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114873": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-029: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114878": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-099: Microsoft OneNote 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114885": {"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-042: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114888": {"CVE-2016-0127"},
	// MS16-042: Microsoft Excel 2007 Service Pack 3
	"3114892": {"CVE-2016-0127", "CVE-2016-0139"},
	// MS16-054: Microsoft Office 2007 Service Pack 3; MS16-099: Microsoft Office 2007 Service Pack 3
	"3114893": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-042: Microsoft Office Compatibility Pack Service Pack 3
	"3114895": {"CVE-2016-0127", "CVE-2016-0139"},
	// MS16-042: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"3114897": {"CVE-2016-0127"},
	// MS16-042: Microsoft Excel Viewer
	"3114898": {"CVE-2016-0127", "CVE-2016-0136"},
	// MS16-029: Microsoft Office Compatibility Pack Service Pack 3
	"3114900": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-029: Microsoft Word 2007 Service Pack 3
	"3114901": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-042: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3114927": {"CVE-2016-0136"},
	// MS16-042: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3114934": {"CVE-2016-0136"},
	// MS16-042: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114937": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3114947": {"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3114964": {"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Office Compatibility Pack Service Pack 3
	"3114982": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Word 2007 Service Pack 3
	"3114983": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Word Viewer
	"3114987": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3114988": {"CVE-2016-0136"},
	// MS16-042: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114990": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3114993": {"CVE-2016-0122", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-042: Microsoft Office Web Apps 2010 Service Pack 2
	"3114994": {"CVE-2016-0136"},
	// MS16-054: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115016": {"CVE-2016-0140", "CVE-2016-0183", "CVE-2016-0198"},
	// MS16-070: Microsoft Visio 2013 Service Pack 1 (32-bit editions) (+ 1 variant)
	"3115020": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS16-054: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115025": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-070: Microsoft Visio 2016 (32-bit edition) (+ 1 variant)
	"3115041": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3234"},
	// MS16-054: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3115094": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-054: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3115103": {"CVE-2016-0140", "CVE-2016-0183", "CVE-2016-0198"},
	// MS16-070: Microsoft Excel 2007 Service Pack 3
	"3115107": {"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-070: Microsoft Office Compatibility Pack Service Pack 3
	"3115111": {"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-107: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit editions) (+ 1 variant)
	"3115112": {"CVE-2016-3357", "CVE-2016-3360"},
	// MS16-088: Microsoft Excel Viewer
	"3115114": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-054: Microsoft Office Compatibility Pack Service Pack 3
	"3115115": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-054: Microsoft Word 2007 Service Pack 3
	"3115116": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-088: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115118": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-107: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3115119": {"CVE-2016-3357", "CVE-2016-3360"},
	// MS16-133: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115120": {"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"},
	// MS16-054: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115121": {"CVE-2016-0126", "CVE-2016-0140"},
	// MS16-054: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115123": {"CVE-2016-0126", "CVE-2016-0140"},
	// MS16-070: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115130": {"CVE-2016-0025", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-054: Microsoft Word Viewer
	"3115132": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-070: Office Online Server
	"3115134": {"CVE-2016-3234"},
	// MS16-133: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3115135": {"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"},
	// MS16-070: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3115144": {"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-133: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115153": {"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244"},
	// MS16-107: Excel Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3115169": {"CVE-2016-3360"},
	// MS16-070: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115173": {"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-070: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3115182": {"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-070: Microsoft Word Viewer
	"3115187": {"CVE-2016-0025", "CVE-2016-3233", "CVE-2016-3235"},
	// MS16-070: Microsoft Office Compatibility Pack Service Pack 3
	"3115194": {"CVE-2016-3233", "CVE-2016-3235"},
	// MS16-070: Microsoft Word 2007 Service Pack 3
	"3115195": {"CVE-2016-3233", "CVE-2016-3235"},
	// MS16-070: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115198": {"CVE-2016-3233", "CVE-2016-3235"},
	// MS16-070: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115243": {"CVE-2016-3233", "CVE-2016-3235"},
	// MS16-088: Microsoft Outlook 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115246": {"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115254": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-099: Microsoft OneNote 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115256": {"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-088: Microsoft Outlook 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115259": {"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115262": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-088: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3115272": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-088: Microsoft Outlook 2016 (32-bit edition) (+ 1 variant)
	"3115279": {"CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3115285": {"CVE-2016-3279", "CVE-2016-3281"},
	// MS16-088: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3115289": {"CVE-2016-3279", "CVE-2016-3281"},
	// MS16-088: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115292": {"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft SharePoint Server 2016
	"3115299": {"CVE-2016-3279", "CVE-2016-3281"},
	// MS16-088: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3115301": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Excel 2007 Service Pack 3
	"3115306": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-088: Microsoft Office Compatibility Pack Service Pack 3
	"3115308": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-088: Microsoft Office Compatibility Pack Service Pack 3
	"3115309": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Word 2007 Service Pack 3
	"3115311": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115315": {"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115317": {"CVE-2016-3278", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115322": {"CVE-2016-3278", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3283"},
	// MS16-088: Office Online Server
	"3115386": {"CVE-2016-3279", "CVE-2016-3281"},
	// MS16-088: Microsoft Word Viewer
	"3115393": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3283", "CVE-2016-3284"},
	// MS16-088: Microsoft Word Viewer
	"3115395": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3284"},
	// MS16-099: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3115415": {"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-099: Microsoft OneNote 2016 (32-bit edition) (+ 1 variant)
	"3115419": {"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-099: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115427": {"CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-099: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3115439": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-107: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3115443": {"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3362", "CVE-2016-3365"},
	// MS16-099: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115449": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-107: Microsoft Excel 2007 Service Pack 3
	"3115459": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-107: Microsoft Office Compatibility Pack Service Pack 3
	"3115462": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-107: Microsoft Excel Viewer
	"3115463": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-054: Microsoft Office Compatibility Pack Service Pack 3
	"3115464": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198"},
	// MS16-054: Microsoft Word 2007 Service Pack 3; MS16-099: Microsoft Word 2007 Service Pack 3
	"3115465": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198", "CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"},
	// MS16-107: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3115466": {"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3362", "CVE-2016-3365"},
	// MS16-107: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115467": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-099: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115468": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"},
	// MS16-099: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3115471": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"},
	// MS16-107: Microsoft Office Web Apps 2010 Service Pack 2
	"3115472": {"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"},
	// MS16-054: Microsoft Word Viewer; MS16-099: Microsoft Word Viewer
	"3115479": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3317", "CVE-2016-3318"},
	// MS16-054: Microsoft Word Viewer; MS16-099: Microsoft Word Viewer
	"3115480": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0198", "CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"},
	// MS16-107: Microsoft PowerPoint 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3115487": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS15-128: Windows 10 for 32-bit Systems (+ 1 variant); MS15-132: Windows 10 for 32-bit Systems (+ 1 variant)
	"3116869": {"CVE-2015-6106", "CVE-2015-6128"},
	// MS15-128: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS15-132: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS15-135: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3116900": {"CVE-2015-6106", "CVE-2015-6108", "CVE-2015-6128", "CVE-2015-6175"},
	// MS16-107: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3118268": {"CVE-2016-0137", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3118270": {"CVE-2016-3358", "CVE-2016-3362", "CVE-2016-3365"},
	// MS16-107: Microsoft Outlook 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3118280": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"},
	// MS16-107: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3118284": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-107: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3118290": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-107: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3118292": {"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Microsoft Outlook 2016 (32-bit edition) (+ 1 variant)
	"3118293": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"},
	// MS16-107: Microsoft Word Viewer
	"3118297": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Office Online Server
	"3118299": {"CVE-2016-3357", "CVE-2016-3360"},
	// MS16-107: Microsoft Office 2007 Service Pack 3
	"3118300": {"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Microsoft Outlook 2007
	"3118303": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"},
	// MS16-107: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118309": {"CVE-2016-0137", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Microsoft Outlook 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118313": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"},
	// MS16-107: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118316": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3364", "CVE-2016-3366"},
	// MS16-133: Microsoft PowerPoint 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118378": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7232"},
	// MS16-148: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118380": {"CVE-2016-7274", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-133: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3118381": {"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7234"},
	// MS16-133: Microsoft PowerPoint Viewer
	"3118382": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7232"},
	// MS16-133: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3118390": {"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232", "CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-133: Microsoft Excel 2007 Service Pack 3
	"3118395": {"CVE-2016-7230", "CVE-2016-7232"},
	// MS16-133: Microsoft Office 2007 Service Pack 3
	"3118396": {"CVE-2016-7233", "CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7245"},
	// MS15-131: Microsoft Excel for Mac 2011
	"3119517": {"CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"},
	// MS15-131: Microsoft Excel 2016 for Mac
	"3119518": {"CVE-2015-6118", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172", "CVE-2015-6177"},
	// MS16-007: Windows 7 for 32-bit Systems Service Pack 1 (+ 6 variants)
	"3121461": {"CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0019", "CVE-2016-0020"},
	// MS16-007: Windows Vista Service Pack 2 (+ 21 variants)
	"3121918": {"CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0018", "CVE-2016-0019", "CVE-2016-0020"},
	// MS16-005: Windows Vista Service Pack 2 (+ 11 variants)
	"3124000": {"CVE-2016-0008"},
	// MS16-005: Windows Vista Service Pack 2 (+ 21 variants)
	"3124001": {"CVE-2016-0009"},
	// MS16-005: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS16-007: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3124263": {"CVE-2016-0009", "CVE-2016-0020"},
	// MS16-005: Windows 10 for 32-bit Systems (+ 1 variant); MS16-007: Windows 10 for 32-bit Systems (+ 1 variant)
	"3124266": {"CVE-2016-0009", "CVE-2016-0020"},
	// MS16-014: Windows Vista Service Pack 2 (+ 10 variants)
	"3126041": {"CVE-2016-0040", "CVE-2016-0041", "CVE-2016-0044"},
	// MS16-014: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3126434": {"CVE-2016-0040", "CVE-2016-0041", "CVE-2016-0042", "CVE-2016-0049"},
	// MS16-014: Windows Vista Service Pack 2 (+ 18 variants)
	"3126587": {"CVE-2016-0040", "CVE-2016-0042", "CVE-2016-0044", "CVE-2016-0049"},
	// MS16-014: Windows Vista Service Pack 2 (+ 18 variants)
	"3126593": {"CVE-2016-0041", "CVE-2016-0044"},
	// MS16-133: Microsoft Office Compatibility Pack Service Pack 3
	"3127889": {"CVE-2016-7230", "CVE-2016-7232"},
	// MS16-148: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit edition) (+ 1 variant)
	"3127892": {"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-133: Microsoft Excel Viewer
	"3127893": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7230", "CVE-2016-7232"},
	// MS16-133: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3127904": {"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232"},
	// MS16-133: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3127921": {"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232"},
	// MS16-133: Word Automation Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3127927": {"CVE-2016-7230", "CVE-2016-7236"},
	// MS16-133: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3127929": {"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7236"},
	// MS16-133: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3127932": {"CVE-2016-7233", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS17-013: Microsoft Office 2007 Service Pack 3
	"3127945": {"CVE-2017-0014"},
	// MS16-133: Microsoft Office Compatibility Pack Service Pack 3
	"3127948": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-133: Microsoft Word 2007
	"3127949": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-133: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3127950": {"CVE-2016-7230", "CVE-2016-7233", "CVE-2016-7236"},
	// MS16-133: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3127951": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-133: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3127953": {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-133: Microsoft Office Web Apps 2010 Service Pack 2
	"3127954": {"CVE-2016-7236"},
	// MS17-013: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3127958": {"CVE-2017-0014"},
	// MS16-133: Microsoft Word Viewer
	"3127962": {"CVE-2016-7234", "CVE-2016-7235", "CVE-2016-7236", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-148: Microsoft Office 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3127968": {"CVE-2016-7274", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Office 2016 (32-bit edition) (+ 1 variant)
	"3127986": {"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Word Viewer
	"3127995": {"CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3128008": {"CVE-2016-7264", "CVE-2016-7268"},
	// MS16-148: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3128016": {"CVE-2016-7264", "CVE-2016-7268"},
	// MS16-148: Microsoft Excel 2007 Service Pack 3
	"3128019": {"CVE-2016-7267", "CVE-2016-7268"},
	// MS16-148: Microsoft Office 2007 Service Pack 3
	"3128020": {"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Office Compatibility Pack Service Pack 3
	"3128022": {"CVE-2016-7267", "CVE-2016-7268"},
	// MS16-148: Microsoft Excel Viewer
	"3128023": {"CVE-2016-7267", "CVE-2016-7268"},
	// MS16-148: Microsoft Office Compatibility Pack Service Pack 3
	"3128024": {"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"},
	// MS16-148: Microsoft Word 2007 Service Pack 3
	"3128025": {"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"},
	// MS16-148: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3128026": {"CVE-2016-7265"},
	// MS16-148: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3128029": {"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3128032": {"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"},
	// MS16-148: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3128034": {"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289"},
	// MS16-148: Microsoft Office Web Apps 2010 Service Pack 2
	"3128035": {"CVE-2016-7265"},
	// MS16-148: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3128037": {"CVE-2016-7264", "CVE-2016-7268"},
	// MS16-148: Microsoft Word Viewer
	"3128043": {"CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291"},
	// MS16-148: Microsoft Word Viewer
	"3128044": {"CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267"},
	// MS16-004: Microsoft Excel for Mac 2011 (+ 2 variants)
	"3133699": {"CVE-2015-0012", "CVE-2016-0012"},
	// MS16-004: Microsoft Excel 2016 for Mac (+ 2 variants)
	"3133711": {"CVE-2015-0012", "CVE-2016-0012"},
	// MS16-015: Microsoft Excel 2016 for Mac (+ 1 variant)
	"3134241": {"CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-014: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3135173": {"CVE-2016-0040", "CVE-2016-0044"},
	// MS16-014: Windows 10 for 32-bit Systems (+ 1 variant)
	"3135174": {"CVE-2016-0040", "CVE-2016-0044"},
	// MS16-028: Windows 8.1 for 32-bit Systems (+ 5 variants)
	"3137513": {"CVE-2016-0118"},
	// MS16-015: Microsoft Excel for Mac 2011 (+ 1 variant)
	"3137721": {"CVE-2016-0053", "CVE-2016-0055", "CVE-2016-0056"},
	// MS16-029: Microsoft Word 2016 for Mac
	"3138327": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-029: Microsoft Word for Mac 2011
	"3138328": {"CVE-2016-0021", "CVE-2016-0057"},
	// MS16-027: Windows 7 for 32-bit Systems Service Pack 1 (+ 7 variants)
	"3138910": {"CVE-2016-0098"},
	// MS16-027: Windows 7 for 32-bit Systems Service Pack 1 (+ 6 variants)
	"3138962": {"CVE-2016-0101"},
	// MS16-027: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3140768": {"CVE-2016-0098"},
	// MS17-013: Microsoft Office 2007 Service Pack 3
	"3141535": {"CVE-2017-0014", "CVE-2017-0060", "CVE-2017-0073"},
	// MS16-042: Microsoft Word 2016 for Mac
	"3142577": {"CVE-2016-0127", "CVE-2016-0136", "CVE-2016-0139"},
	// MS16-079: Microsoft Exchange Server 2007 Service Pack 3
	"3151086": {"CVE-2016-0028"},
	// MS16-079: Microsoft Exchange Server 2010 Service Pack 3
	"3151097": {"CVE-2016-0028"},
	// MS16-062: Windows Vista Service Pack 2 (+ 18 variants)
	"3153199": {"CVE-2016-0176", "CVE-2016-0197"},
	// MS16-042: Microsoft Word for Mac 2011
	"3154208": {"CVE-2016-0122", "CVE-2016-0127", "CVE-2016-0136"},
	// MS16-054: Microsoft Word for Mac 2011
	"3155776": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-054: Microsoft Word 2016 for Mac
	"3155777": {"CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183"},
	// MS16-055: Windows Vista Service Pack 2 (+ 18 variants)
	"3156013": {"CVE-2016-0184", "CVE-2016-0195"},
	// MS16-055: Windows Vista Service Pack 2 (+ 17 variants)
	"3156016": {"CVE-2016-0168", "CVE-2016-0169", "CVE-2016-0170", "CVE-2016-0195"},
	// MS16-062: Windows Vista Service Pack 2 (+ 18 variants)
	"3156017": {"CVE-2016-0171", "CVE-2016-0173", "CVE-2016-0174", "CVE-2016-0175", "CVE-2016-0196"},
	// MS16-055: Windows Vista Service Pack 2 (+ 18 variants)
	"3156019": {"CVE-2016-0168", "CVE-2016-0169", "CVE-2016-0170", "CVE-2016-0184"},
	// MS16-053: VBScript 5.7 on Windows Server 2008 for 32-bit Systems Service Pack 2
	"3156764": {"CVE-2016-0187"},
	// MS16-053: VBScript 5.7 on Windows Vista Service Pack 2 (+ 3 variants)
	"3158991": {"CVE-2016-0187"},
	// MS16-073: Windows Vista Service Pack 2 (+ 18 variants)
	"3161664": {"CVE-2016-3232"},
	// MS16-073: Windows 10 for 32-bit Systems (+ 1 variant); MS16-080: Windows 10 for 32-bit Systems (+ 1 variant)
	"3163017": {"CVE-2016-3215", "CVE-2016-3232"},
	// MS16-073: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3163018": {"CVE-2016-3232"},
	// MS16-074: Windows Vista Service Pack 2 (+ 18 variants)
	"3164033": {"CVE-2016-3216", "CVE-2016-3219"},
	// MS16-074: Windows Vista Service Pack 2 (+ 18 variants)
	"3164035": {"CVE-2016-3219", "CVE-2016-3220"},
	// MS16-073: Windows Server 2012 (+ 3 variants)
	"3164294": {"CVE-2016-3218", "CVE-2016-3221"},
	// MS16-070: Microsoft Word for Mac 2011
	"3165796": {"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-070: Microsoft Word 2016 for Mac
	"3165798": {"CVE-2016-3233", "CVE-2016-3234", "CVE-2016-3235"},
	// MS16-101: Windows Vista Service Pack 2 (+ 6 variants)
	"3167679": {"CVE-2016-3300"},
	// MS16-092: Windows 8.1 for 32-bit Systems (+ 6 variants)
	"3169704": {"CVE-2016-3258"},
	// MS16-092: Windows 8.1 for 32-bit Systems (+ 6 variants)
	"3170377": {"CVE-2016-3272"},
	// MS16-088: Microsoft Excel 2016 for Mac (+ 1 variant)
	"3170460": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3283"},
	// MS16-088: Microsoft Excel for Mac 2011 (+ 1 variant)
	"3170463": {"CVE-2016-3278", "CVE-2016-3279", "CVE-2016-3283"},
	// MS17-014: Excel Services on Microsoft SharePoint Server 2013 Service Pack 1
	"3172431": {"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"},
	// MS17-014: Microsoft Office Web Apps Server 2013 Service Pack 1
	"3172457": {"CVE-2017-0006", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"},
	// MS17-014: Microsoft Word 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3172464": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"},
	// MS17-014: Microsoft Excel 2013 Service Pack 1 (32-bit editions) (+ 2 variants)
	"3172542": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"},
	// MS16-097: Windows 10 for 32-bit Systems (+ 1 variant)
	"3176492": {"CVE-2016-3303", "CVE-2016-3304"},
	// MS16-097: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3176493": {"CVE-2016-3303", "CVE-2016-3304"},
	// MS16-097: Windows 10 Version 1607 for 32-bit Systems (+ 1 variant)
	"3176495": {"CVE-2016-3303", "CVE-2016-3304"},
	// MS16-101: Windows 8.1 for 32-bit Systems (+ 6 variants)
	"3177108": {"CVE-2016-3237"},
	// MS17-013: Microsoft Word Viewer
	"3178653": {"CVE-2017-0014", "CVE-2017-0060", "CVE-2017-0073"},
	// MS17-014: Microsoft Excel 2016 (32-bit edition) (+ 1 variant)
	"3178673": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-014: Microsoft Word 2016 (32-bit edition) (+ 1 variant)
	"3178674": {"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"},
	// MS17-014: Microsoft Excel 2007 Service Pack 3
	"3178676": {"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-014: Microsoft Office Compatibility Pack Service Pack 3
	"3178677": {"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-014: Excel Services on Microsoft SharePoint Server 2007 Service Pack 3 (32-bit edition) (+ 1 variant)
	"3178678": {"CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0030", "CVE-2017-0105"},
	// MS17-014: Microsoft Excel Viewer
	"3178680": {"CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-014: Microsoft Office Compatibility Pack Service Pack 3
	"3178682": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0052"},
	// MS17-014: Microsoft Word 2007 Service Pack 3
	"3178683": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0052"},
	// MS17-014: Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3178684": {"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"},
	// MS17-014: Excel Services on Microsoft SharePoint Server 2010 Service Pack 2
	"3178685": {"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0030", "CVE-2017-0052", "CVE-2017-0105"},
	// MS17-014: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3178686": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"},
	// MS17-014: Microsoft Word 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3178687": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"},
	// MS17-013: Microsoft Office 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3178688": {"CVE-2017-0060", "CVE-2017-0073"},
	// MS17-014: Microsoft Office Web Apps 2010 Service Pack 2
	"3178689": {"CVE-2017-0006", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0052"},
	// MS17-014: Microsoft Excel 2010 Service Pack 2 (32-bit editions) (+ 1 variant)
	"3178690": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-013: Microsoft Word Viewer
	"3178693": {"CVE-2017-0014"},
	// MS17-014: Microsoft Word Viewer
	"3178694": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0105"},
	// MS16-099: Microsoft Word for Mac 2011
	"3179162": {"CVE-2016-3313", "CVE-2016-3315", "CVE-2016-3316", "CVE-2016-3318"},
	// MS16-099: Microsoft OneNote 2016 for Mac (+ 1 variant)
	"3179163": {"CVE-2016-3318"},
	// MS16-123: Windows Vista Service Pack 2 (+ 6 variants)
	"3183431": {"CVE-2016-3266", "CVE-2016-3341", "CVE-2016-3376", "CVE-2016-7211"},
	// MS16-110: Windows Vista Service Pack 2 (+ 16 variants)
	"3184471": {"CVE-2016-3346", "CVE-2016-3352", "CVE-2016-3369"},
	// MS16-108: Microsoft Exchange Server 2007 Service Pack 3
	"3184711": {"CVE-2016-3378", "CVE-2016-3379"},
	// MS16-108: Microsoft Exchange Server 2010 Service Pack 3
	"3184728": {"CVE-2016-3378", "CVE-2016-3379"},
	// MS16-101: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-123: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-124: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3185330": {"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079", "CVE-2016-3300", "CVE-2016-3341"},
	// MS16-101: Windows 8.1 for 32-bit Systems (+ 4 variants); MS16-124: Windows 8.1 for 32-bit Systems (+ 4 variants)
	"3185331": {"CVE-2016-0079", "CVE-2016-3300"},
	// MS16-101: Windows Server 2012 (+ 1 variant); MS16-124: Windows Server 2012 (+ 1 variant)
	"3185332": {"CVE-2016-0079", "CVE-2016-3300"},
	// MS16-106: Windows 10 for 32-bit Systems (+ 1 variant); MS16-111: Windows 10 for 32-bit Systems (+ 1 variant)
	"3185611": {"CVE-2016-3356", "CVE-2016-3372"},
	// MS16-106: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS16-111: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3185614": {"CVE-2016-3356", "CVE-2016-3372"},
	// MS16-107: Microsoft Visio 2016 (32-bit editions)
	"3185852": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-106: Windows Vista Service Pack 2 (+ 18 variants)
	"3185911": {"CVE-2016-3356"},
	// MS16-107: Microsoft Word for Mac 2011
	"3186805": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3358", "CVE-2016-3359", "CVE-2016-3360", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3366", "CVE-2016-3381"},
	// MS16-107: Microsoft Excel 2016 for Mac (+ 3 variants)
	"3186807": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3359", "CVE-2016-3361", "CVE-2016-3362", "CVE-2016-3363", "CVE-2016-3364", "CVE-2016-3365", "CVE-2016-3381"},
	// MS16-110: Windows 8.1 for 32-bit Systems (+ 2 variants)
	"3187754": {"CVE-2016-3346", "CVE-2016-3368", "CVE-2016-3369"},
	// MS16-106: Windows 10 Version 1607 for 32-bit Systems (+ 1 variant); MS16-110: Windows 10 Version 1607 for 32-bit Systems (+ 1 variant); MS16-111: Windows 10 Version 1607 for 32-bit Systems (+ 1 variant)
	"3189866": {"CVE-2016-3349", "CVE-2016-3369", "CVE-2016-3372"},
	// MS16-123: Windows Vista Service Pack 2 (+ 6 variants)
	"3191203": {"CVE-2016-3341", "CVE-2016-7185"},
	// MS16-124: Windows Vista Service Pack 2 (+ 6 variants)
	"3191256": {"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079"},
	// MS16-101: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-123: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-124: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3192391": {"CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079", "CVE-2016-3300", "CVE-2016-3341"},
	// MS16-101: Windows 8.1 for 32-bit Systems (+ 3 variants); MS16-124: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3192392": {"CVE-2016-0079", "CVE-2016-3300"},
	// MS16-101: Windows Server 2012 (+ 1 variant); MS16-124: Windows Server 2012 (+ 1 variant)
	"3192393": {"CVE-2016-0079", "CVE-2016-3300"},
	// MS16-101: Windows 10 for 32-bit Systems (+ 1 variant)
	"3192440": {"CVE-2016-3300"},
	// MS16-101: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3192441": {"CVE-2016-3300"},
	// MS16-135: Windows Vista Service Pack 2 (+ 6 variants)
	"3194371": {"CVE-2016-7214", "CVE-2016-7215", "CVE-2016-7246"},
	// MS16-136: Microsoft SQL Server 2014 Service Pack 2 for 32-bit Systems (+ 1 variant)
	"3194714": {"CVE-2016-7249", "CVE-2016-7251", "CVE-2016-7252", "CVE-2016-7254"},
	// MS16-136: Microsoft SQL Server 2016 for x64-based Systems
	"3194716": {"CVE-2016-7253", "CVE-2016-7254"},
	// MS16-136: Microsoft SQL Server 2012 for 32-bit Systems Service Pack 2 (+ 1 variant)
	"3194719": {"CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252"},
	// MS16-136: Microsoft SQL Server 2014 Service Pack 1 for 32-bit Systems (+ 1 variant)
	"3194720": {"CVE-2016-7249", "CVE-2016-7251", "CVE-2016-7252", "CVE-2016-7254"},
	// MS16-136: Microsoft SQL Server 2012 for 32-bit Systems Service Pack 3 (+ 1 variant)
	"3194721": {"CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252"},
	// MS16-101: Windows 10 Version 1607 for 32-bit Systems (+ 1 variant)
	"3194798": {"CVE-2016-3300"},
	// MS16-132: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-137: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3197867": {"CVE-2016-7217", "CVE-2016-7220"},
	// MS16-132: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS16-137: Windows 7 for 32-bit Systems Service Pack 1 (+ 3 variants)
	"3197868": {"CVE-2016-7217", "CVE-2016-7220"},
	// MS16-137: Windows 8.1 for 32-bit Systems (+ 3 variants); MS16-138: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3197873": {"CVE-2016-7220", "CVE-2016-7225", "CVE-2016-7226"},
	// MS16-137: Windows 8.1 for 32-bit Systems (+ 4 variants); MS16-138: Windows 8.1 for 32-bit Systems (+ 4 variants)
	"3197874": {"CVE-2016-7220", "CVE-2016-7225", "CVE-2016-7226"},
	// MS16-137: Windows Server 2012 (+ 1 variant); MS16-138: Windows Server 2012 (+ 1 variant)
	"3197876": {"CVE-2016-7220", "CVE-2016-7225", "CVE-2016-7226"},
	// MS16-137: Windows Server 2012 (+ 1 variant); MS16-138: Windows Server 2012 (+ 1 variant)
	"3197877": {"CVE-2016-7220", "CVE-2016-7225", "CVE-2016-7226"},
	// MS16-135: Windows Vista Service Pack 2 (+ 6 variants)
	"3198234": {"CVE-2016-7218", "CVE-2016-7246"},
	// MS16-137: Windows Vista Service Pack 2 (+ 6 variants)
	"3198510": {"CVE-2016-7220"},
	// MS16-137: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3198586": {"CVE-2016-7220"},
	// MS16-133: Microsoft Excel 2016 for Mac (+ 1 variant)
	"3198798": {"CVE-2016-7230", "CVE-2016-7231", "CVE-2016-7232", "CVE-2016-7233", "CVE-2016-7235", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-148: Microsoft Excel 2016 for Mac (+ 1 variant)
	"3198800": {"CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7300"},
	// MS16-133: Microsoft Excel for Mac 2011 (+ 1 variant)
	"3198807": {"CVE-2016-7230", "CVE-2016-7244", "CVE-2016-7245"},
	// MS16-148: Microsoft Excel for Mac 2011 (+ 2 variants)
	"3198808": {"CVE-2016-7266", "CVE-2016-7300"},
	// MS16-137: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants)
	"3200970": {"CVE-2016-7220"},
	// MS16-132: Windows Vista Service Pack 2 (+ 6 variants)
	"3203859": {"CVE-2016-7205", "CVE-2016-7217"},
	// MS16-148: Microsoft Auto Updater for Mac
	"3204068": {"CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7266", "CVE-2016-7268"},
	// MS16-146: Windows Vista Service Pack 2 (+ 6 variants)
	"3204724": {"CVE-2016-7272", "CVE-2016-7273"},
	// MS16-146: Windows 10 for 32-bit Systems (+ 1 variant)
	"3205383": {"CVE-2016-7257"},
	// MS16-146: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"3205386": {"CVE-2016-7257"},
	// MS16-146: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3205394": {"CVE-2016-7273"},
	// MS16-146: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"3205400": {"CVE-2016-7257", "CVE-2016-7273"},
	// MS16-146: Windows 8.1 for 32-bit Systems (+ 4 variants)
	"3205401": {"CVE-2016-7257", "CVE-2016-7273"},
	// MS16-146: Windows Server 2012 (+ 1 variant)
	"3205408": {"CVE-2016-7257", "CVE-2016-7273"},
	// MS16-146: Windows Server 2012 (+ 1 variant)
	"3205409": {"CVE-2016-7257", "CVE-2016-7273"},
	// MS16-146: Windows Vista Service Pack 2 (+ 6 variants)
	"3205638": {"CVE-2016-7257", "CVE-2016-7273"},
	// MS16-155: Windows Vista for 32-bit Systems Service Pack 2 (+ 16 variants)
	"3205640": {"CVE-2016-7270"},
	// MS16-146: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants)
	"3206632": {"CVE-2016-7257"},
	// MS16-146: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"3207752": {"CVE-2016-7273"},
	// MS17-008: Windows Server 2008 for x64-based Systems Service Pack 2 (+ 1 variant)
	"3211306": {"CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0074", "CVE-2017-0095", "CVE-2017-0098"},
	// MS17-012: Windows Vista Service Pack 2 (+ 6 variants)
	"3217587": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0057", "CVE-2017-0100", "CVE-2017-0104"},
	// MS17-012: Windows Server 2008 for 32-bit Systems Service Pack 2 (+ 1 variant)
	"4012021": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0039", "CVE-2017-0057", "CVE-2017-0100"},
	// MS17-008: Windows 7 for x64-based Systems Service Pack 1 (+ 2 variants); MS17-012: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS17-017: Windows 7 for x64-based Systems Service Pack 1 (+ 2 variants); MS17-018: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"4012212": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0051", "CVE-2017-0057", "CVE-2017-0074", "CVE-2017-0078", "CVE-2017-0095", "CVE-2017-0098"},
	// MS17-008: Windows 8.1 for x64-based Systems (+ 2 variants); MS17-011: Windows 8.1 for 32-bit Systems (+ 3 variants); MS17-012: Windows 8.1 for 32-bit Systems (+ 3 variants); MS17-013: Windows 8.1 for 32-bit Systems (+ 3 variants); MS17-017: Windows 8.1 for 32-bit Systems (+ 3 variants); MS17-018: Windows 8.1 for 32-bit Systems (+ 3 variants)
	"4012213": {"CVE-2017-0007", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0080", "CVE-2017-0082", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0095", "CVE-2017-0098", "CVE-2017-0101", "CVE-2017-0103", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-008: Windows Server 2012 (+ 1 variant); MS17-011: Windows Server 2012 (+ 1 variant); MS17-012: Windows Server 2012 (+ 1 variant); MS17-013: Windows Server 2012 (+ 1 variant); MS17-017: Windows Server 2012 (+ 1 variant); MS17-018: Windows Server 2012 (+ 1 variant)
	"4012214": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0057", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0079", "CVE-2017-0080", "CVE-2017-0082", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0095", "CVE-2017-0098", "CVE-2017-0101", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-008: Windows 7 for x64-based Systems Service Pack 1 (+ 2 variants); MS17-012: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants); MS17-017: Windows 7 for x64-based Systems Service Pack 1 (+ 2 variants); MS17-018: Windows 7 for 32-bit Systems Service Pack 1 (+ 4 variants)
	"4012215": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0051", "CVE-2017-0057", "CVE-2017-0074", "CVE-2017-0078", "CVE-2017-0095", "CVE-2017-0098"},
	// MS17-008: Windows 8.1 for x64-based Systems (+ 2 variants); MS17-011: Windows 8.1 for 32-bit Systems (+ 4 variants); MS17-012: Windows 8.1 for 32-bit Systems (+ 4 variants); MS17-013: Windows 8.1 for 32-bit Systems (+ 4 variants); MS17-017: Windows 8.1 for 32-bit Systems (+ 4 variants); MS17-018: Windows 8.1 for 32-bit Systems (+ 4 variants)
	"4012216": {"CVE-2017-0007", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0080", "CVE-2017-0082", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0095", "CVE-2017-0098", "CVE-2017-0101", "CVE-2017-0103", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-008: Windows Server 2012 (+ 1 variant); MS17-011: Windows Server 2012 (+ 1 variant); MS17-012: Windows Server 2012 (+ 1 variant); MS17-013: Windows Server 2012 (+ 1 variant); MS17-017: Windows Server 2012 (+ 1 variant); MS17-018: Windows Server 2012 (+ 1 variant)
	"4012217": {"CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0057", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0079", "CVE-2017-0080", "CVE-2017-0082", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0095", "CVE-2017-0098", "CVE-2017-0101", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-013: Windows Vista Service Pack 2 (+ 6 variants); MS17-018: Windows Vista Service Pack 2 (+ 6 variants)
	"4012497": {"CVE-2017-0014", "CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0038", "CVE-2017-0060", "CVE-2017-0061", "CVE-2017-0062", "CVE-2017-0063", "CVE-2017-0073", "CVE-2017-0078", "CVE-2017-0108"},
	// MS17-013: Windows Vista Service Pack 2 (+ 6 variants)
	"4012583": {"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0047", "CVE-2017-0061", "CVE-2017-0063"},
	// MS17-013: Windows Vista Service Pack 2 (+ 6 variants)
	"4012584": {"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0038", "CVE-2017-0047", "CVE-2017-0060", "CVE-2017-0062", "CVE-2017-0073", "CVE-2017-0108"},
	// MS17-008: Windows 10 for x64-based Systems; MS17-011: Windows 10 for 32-bit Systems (+ 1 variant); MS17-012: Windows 10 for 32-bit Systems (+ 1 variant); MS17-013: Windows 10 for 32-bit Systems (+ 1 variant); MS17-017: Windows 10 for 32-bit Systems (+ 1 variant); MS17-018: Windows 10 for 32-bit Systems (+ 1 variant)
	"4012606": {"CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0101", "CVE-2017-0103", "CVE-2017-0104", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-008: Windows 10 Version 1511 for x64-based Systems; MS17-011: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS17-012: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS17-013: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS17-017: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant); MS17-018: Windows 10 Version 1511 for 32-bit Systems (+ 1 variant)
	"4013198": {"CVE-2017-0021", "CVE-2017-0024", "CVE-2017-0039", "CVE-2017-0051", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0101", "CVE-2017-0103", "CVE-2017-0104", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-014: Microsoft Excel for Mac 2011 (+ 3 variants)
	"4013241": {"CVE-2017-0006", "CVE-2017-0019", "CVE-2017-0020", "CVE-2017-0027", "CVE-2017-0029", "CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0052", "CVE-2017-0053", "CVE-2017-0105"},
	// MS17-011: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants); MS17-012: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants); MS17-013: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants); MS17-017: Windows 10 Version 1607 for 32-bit Systems (+ 3 variants); MS17-018: Windows Server 2016 for x64-based Systems (+ 3 variants)
	"4013429": {"CVE-2017-0039", "CVE-2017-0061", "CVE-2017-0072", "CVE-2017-0079", "CVE-2017-0082", "CVE-2017-0083", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0101", "CVE-2017-0103", "CVE-2017-0108", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	// MS17-013: Windows Vista Service Pack 2 (+ 4 variants)
	"4017018": {"CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0014", "CVE-2017-0025", "CVE-2017-0047", "CVE-2017-0060", "CVE-2017-0061", "CVE-2017-0062", "CVE-2017-0063", "CVE-2017-0073", "CVE-2017-0108"},
	// MS16-111: Windows 10 Version 1703 for 32-bit Systems (+ 1 variant)
	"4025342": {"CVE-2016-3306", "CVE-2016-3371", "CVE-2016-3372", "CVE-2016-3373"},
	// MS16-039: Windows 10 Version 1703 for 32-bit Systems (+ 1 variant)
	"4038788": {"CVE-2016-0143", "CVE-2016-0145", "CVE-2016-0167"},
	// MS16-039: Windows 10 Version 1709 for 32-bit Systems (+ 1 variant)
	"4093112": {"CVE-2016-0145", "CVE-2016-0165", "CVE-2016-0167"},
}

// bulletinArchiveComponentNotApplicable lists per-bulletin component-keyed
// NA CVEs from the archive markdown's per-vulnerability tables. Three
// flavors share the same map shape, distinguished by what the inner key
// represents and which markdown table the entries are sourced from:
//
//   - IE Cumulative bulletins (MS14-010 through MS17-006) use a shared
//     IE/Edge vocabulary, one inner key per IE version: "Internet Explorer
//     6", "Internet Explorer 7", "Internet Explorer 8", "Internet Explorer
//     9", "Internet Explorer 10", "Internet Explorer 11", "Internet
//     Explorer 11 on Windows 10", and "Microsoft Edge". Sourced from the
//     "Severity Ratings and Impact" table (CVE rows × IE-version columns).
//   - Older Office / Windows / Word / WMP bulletins (MS06-012, MS06-020,
//     MS06-039, MS06-078) use bulletin-specific product strings, taken
//     verbatim from the bulletin's markdown column header (e.g.
//     "Microsoft PowerPoint 2000", "Windows Server 2003", "Microsoft
//     Project 2000", "Windows Media Player 6.4 (All operating systems)").
//     MS06-060 is handled by KB-keyed entries instead — see
//     bulletinArchiveKBNotApplicable comments for KB923088/923089/923090/
//     924998/924999.
//   - Mixed-applicability bulletins (MS12-054, MS12-074, MS13-046,
//     MS13-081, MS15-097, MS15-128, MS16-014/015/045/062/067/088/090/
//     097/099/106/107/108/111/133/135/148, MS17-012/013/017/018) use the
//     row's xlsx affected_product string verbatim (whitespace-normalized)
//     as the inner key. Sourced from the per-CVE matrix tables that
//     share a KB across multiple xlsx rows with differing per-CVE NA
//     status — see the case clause in normalizeArchiveComponentKey for
//     the dispatch list and rationale.
//
// At extract time, the row's (bulletin_id, affected_product, affected_component)
// is normalized via normalizeArchiveComponentKey() and matched against
// this map. For the third flavor, the inner key must match the
// affected_product cell of the row exactly after whitespace
// normalization, so map entries should be copied verbatim from xlsx
// (note e.g. the space before "(Server Core installation)" in
// MS17-018's keys).
var bulletinArchiveComponentNotApplicable = map[string]map[string][]string{
	"MS06-012": {
		"Microsoft PowerPoint 2000": {"CVE-2005-4131", "CVE-2006-0028", "CVE-2006-0029", "CVE-2006-0030", "CVE-2006-0031"},
		"Microsoft PowerPoint 2002": {"CVE-2005-4131", "CVE-2006-0028", "CVE-2006-0029", "CVE-2006-0030", "CVE-2006-0031"},
	},
	"MS06-020": {
		"Windows 2000":                       {"CVE-2005-2628", "CVE-2006-0024"},
		"Windows Server 2003":                {"CVE-2005-2628", "CVE-2006-0024"},
		"Windows Server 2003 Service Pack 1": {"CVE-2005-2628", "CVE-2006-0024"},
	},
	"MS06-039": {
		"Microsoft Project 2000": {"CVE-2006-0033"},
	},
	"MS06-078": {
		"Windows Media Player 6.4 (All operating systems)": {"CVE-2006-6134"},
	},
	"MS12-054": {
		"Windows 7 for 32-bit Systems":                                                           {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows 7 for x64-based Systems":                                                        {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2003 Service Pack 2":                                                     {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2003 with SP2 for Itanium-based Systems":                                 {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2003 x64 Edition Service Pack 2":                                         {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for Itanium-based Systems":                                       {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for x64-based Systems":                                           {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for x64-based Systems (Server Core installation)":                {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                                  {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":       {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                           {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                               {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)":    {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Vista Service Pack 2":                                                           {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows Vista x64 Edition Service Pack 2":                                               {"CVE-2012-1852", "CVE-2012-1853"},
		"Windows XP Professional x64 Edition Service Pack 2":                                     {"CVE-2012-1853"},
	},
	"MS12-074": {
		"Microsoft .NET Framework 3.5 on Windows 8 for 32-bit Systems":    {"CVE-2012-1895"},
		"Microsoft .NET Framework 3.5 on Windows 8 for x64-based Systems": {"CVE-2012-1895"},
		"Microsoft .NET Framework 3.5 on Windows Server 2012":             {"CVE-2012-1895"},
	},
	"MS13-046": {
		"Windows 8 for 32-bit Systems (ntoskrnl.exe)":                                                         {"CVE-2013-1333"},
		"Windows 8 for 64-bit Systems (ntoskrnl.exe)":                                                         {"CVE-2013-1333"},
		"Windows RT (ntoskrnl.exe)":                                                                           {"CVE-2013-1333"},
		"Windows Server 2003 Service Pack 2 (Win32k.sys)":                                                     {"CVE-2013-1333"},
		"Windows Server 2003 with SP2 for Itanium-based Systems (Win32k.sys)":                                 {"CVE-2013-1333"},
		"Windows Server 2003 x64 Edition Service Pack 2 (Win32k.sys)":                                         {"CVE-2013-1333"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1 (Win32k.sys)":                        {"CVE-2013-1333"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation) (Win32k.sys)": {"CVE-2013-1333"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Win32k.sys)":                            {"CVE-2013-1333"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation) (Win32k.sys)":       {"CVE-2013-1333"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Win32k.sys)":                                  {"CVE-2013-1333"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2 (Win32k.sys)":                           {"CVE-2013-1333"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation) (Win32k.sys)":    {"CVE-2013-1333"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Win32k.sys)":                               {"CVE-2013-1333"},
		"Windows Server 2012 (Server Core installation) (ntoskrnl.exe)":                                       {"CVE-2013-1333"},
		"Windows Server 2012 (ntoskrnl.exe)":                                                                  {"CVE-2013-1333"},
		"Windows Vista Service Pack 2 (Win32k.sys)":                                                           {"CVE-2013-1333"},
		"Windows Vista x64 Edition Service Pack 2 (Win32k.sys)":                                               {"CVE-2013-1333"},
		"Windows XP Professional x64 Edition Service Pack 2 (Win32k.sys)":                                     {"CVE-2013-1333"},
		"Windows XP Service Pack 3 (Win32k.sys)":                                                              {"CVE-2013-1333"},
	},
	"MS13-081": {
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2013-3880"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2013-3880"},
		"Windows 8 for 32-bit Systems":                                                           {"CVE-2013-3881"},
		"Windows 8 for 64-bit Systems":                                                           {"CVE-2013-3881"},
		"Windows RT":                                                                             {"CVE-2013-3881"},
		"Windows Server 2003 Service Pack 2":                                                     {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2003 with SP2 for Itanium-based Systems":                                 {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2003 x64 Edition Service Pack 2":                                         {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2013-3880"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2013-3880"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2013-3880"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                                  {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":       {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                           {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                               {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Server 2012":                                                                    {"CVE-2013-3881"},
		"Windows Server 2012 (Server Core installation)":                                         {"CVE-2013-3881"},
		"Windows Vista Service Pack 2":                                                           {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows Vista x64 Edition Service Pack 2":                                               {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows XP Professional x64 Edition Service Pack 2":                                     {"CVE-2013-3880", "CVE-2013-3881"},
		"Windows XP Service Pack 3":                                                              {"CVE-2013-3880", "CVE-2013-3881"},
	},
	"MS14-010": {
		"Internet Explorer 6":  {"CVE-2014-0267", "CVE-2014-0268", "CVE-2014-0270", "CVE-2014-0272", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0281", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0287", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"},
		"Internet Explorer 7":  {"CVE-2014-0267", "CVE-2014-0268", "CVE-2014-0270", "CVE-2014-0272", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0281", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0287", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"},
		"Internet Explorer 8":  {"CVE-2014-0267", "CVE-2014-0270", "CVE-2014-0273", "CVE-2014-0274", "CVE-2014-0283", "CVE-2014-0284", "CVE-2014-0288", "CVE-2014-0289", "CVE-2014-0290", "CVE-2014-0293"},
		"Internet Explorer 9":  {"CVE-2014-0267", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0289", "CVE-2014-0290"},
		"Internet Explorer 10": {"CVE-2014-0267", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0283", "CVE-2014-0289", "CVE-2014-0290"},
		"Internet Explorer 11": {"CVE-2014-0269", "CVE-2014-0272", "CVE-2014-0276", "CVE-2014-0277", "CVE-2014-0278", "CVE-2014-0279", "CVE-2014-0280", "CVE-2014-0283", "CVE-2014-0284"},
	},
	"MS14-012": {
		"Internet Explorer 6":  {"CVE-2014-0297", "CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0308", "CVE-2014-0309", "CVE-2014-0312", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-0324", "CVE-2014-4112"},
		"Internet Explorer 7":  {"CVE-2014-0297", "CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0308", "CVE-2014-0309", "CVE-2014-0312", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-0324", "CVE-2014-4112"},
		"Internet Explorer 8":  {"CVE-2014-0298", "CVE-2014-0304", "CVE-2014-0307", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321", "CVE-2014-0322", "CVE-2014-4112"},
		"Internet Explorer 9":  {"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0304", "CVE-2014-0313", "CVE-2014-0321", "CVE-2014-4112"},
		"Internet Explorer 10": {"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0304", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-4112"},
		"Internet Explorer 11": {"CVE-2014-0302", "CVE-2014-0303", "CVE-2014-0306", "CVE-2014-0307", "CVE-2014-0309", "CVE-2014-0314", "CVE-2014-0322"},
	},
	"MS14-018": {
		"Internet Explorer 6":  {"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1755", "CVE-2014-1760"},
		"Internet Explorer 7":  {"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1755", "CVE-2014-1760"},
		"Internet Explorer 8":  {"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1755", "CVE-2014-1760"},
		"Internet Explorer 9":  {"CVE-2014-1752", "CVE-2014-1760"},
		"Internet Explorer 10": {"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1753", "CVE-2014-1755", "CVE-2014-1760"},
		"Internet Explorer 11": {"CVE-2014-0325", "CVE-2014-1751", "CVE-2014-1752", "CVE-2014-1753", "CVE-2014-1755"},
	},
	"MS14-035": {
		"Internet Explorer 6":  {"CVE-2014-1764", "CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1778", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1791", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1797", "CVE-2014-1800", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777", "CVE-2014-2782"},
		"Internet Explorer 7":  {"CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1778", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1796", "CVE-2014-1797", "CVE-2014-1800", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777", "CVE-2014-2782"},
		"Internet Explorer 8":  {"CVE-2014-1766", "CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1777", "CVE-2014-1780", "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785", "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1794", "CVE-2014-1795", "CVE-2014-1797", "CVE-2014-1802", "CVE-2014-1805", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765", "CVE-2014-2766", "CVE-2014-2767", "CVE-2014-2769", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2782"},
		"Internet Explorer 9":  {"CVE-2014-1769", "CVE-2014-1772", "CVE-2014-1777", "CVE-2014-1780", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1785", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1797", "CVE-2014-1802", "CVE-2014-1804", "CVE-2014-2753", "CVE-2014-2755", "CVE-2014-2756", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2769", "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2773", "CVE-2014-2776"},
		"Internet Explorer 10": {"CVE-2014-1769", "CVE-2014-1774", "CVE-2014-1781", "CVE-2014-1782", "CVE-2014-1785", "CVE-2014-1788", "CVE-2014-1792", "CVE-2014-1804", "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2760", "CVE-2014-2761", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2770", "CVE-2014-2772", "CVE-2014-2773", "CVE-2014-2776"},
		"Internet Explorer 11": {"CVE-2014-1774", "CVE-2014-1781", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790", "CVE-2014-1792", "CVE-2014-1804", "CVE-2014-2754", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2770", "CVE-2014-2773"},
	},
	"MS14-037": {
		"Internet Explorer 6":  {"CVE-2014-1763", "CVE-2014-2783", "CVE-2014-2785", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2789", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2795", "CVE-2014-2798", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2803", "CVE-2014-2804", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"},
		"Internet Explorer 7":  {"CVE-2014-1763", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2789", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2795", "CVE-2014-2798", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2803", "CVE-2014-2804", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"},
		"Internet Explorer 8":  {"CVE-2014-1763", "CVE-2014-2785", "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2794", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-2813", "CVE-2014-4066"},
		"Internet Explorer 9":  {"CVE-2014-2785", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-4066"},
		"Internet Explorer 10": {"CVE-2014-2785", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2802", "CVE-2014-2806", "CVE-2014-4066"},
		"Internet Explorer 11": {"CVE-2014-2785", "CVE-2014-2788", "CVE-2014-2791", "CVE-2014-2794", "CVE-2014-2797", "CVE-2014-2803"},
	},
	"MS14-051": {
		"Internet Explorer 6":  {"CVE-2014-2784", "CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2819", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4051", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4056", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"},
		"Internet Explorer 7":  {"CVE-2014-2784", "CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4051", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"},
		"Internet Explorer 8":  {"CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4052", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4058", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"},
		"Internet Explorer 9":  {"CVE-2014-2796", "CVE-2014-2808", "CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2818", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-2825", "CVE-2014-4050", "CVE-2014-4055", "CVE-2014-4057", "CVE-2014-4067", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"},
		"Internet Explorer 10": {"CVE-2014-2810", "CVE-2014-2811", "CVE-2014-2821", "CVE-2014-2822", "CVE-2014-2823", "CVE-2014-2824", "CVE-2014-4057", "CVE-2014-4145", "CVE-2014-6354", "CVE-2014-8985"},
		"Internet Explorer 11": {"CVE-2014-2818", "CVE-2014-2821", "CVE-2014-2824", "CVE-2014-4052", "CVE-2014-4056"},
	},
	"MS14-052": {
		"Internet Explorer 6":  {"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4092", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4098", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"},
		"Internet Explorer 7":  {"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4092", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4098", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"},
		"Internet Explorer 8":  {"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4099", "CVE-2014-4101", "CVE-2014-4102"},
		"Internet Explorer 9":  {"CVE-2014-4080", "CVE-2014-4084", "CVE-2014-4086", "CVE-2014-4087", "CVE-2014-4089", "CVE-2014-4091", "CVE-2014-4093", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4101", "CVE-2014-4102"},
		"Internet Explorer 10": {"CVE-2014-4086", "CVE-2014-4087", "CVE-2014-4095", "CVE-2014-4096", "CVE-2014-4101"},
		"Internet Explorer 11": {"CVE-2014-4082", "CVE-2014-4084", "CVE-2014-4086", "CVE-2014-4093"},
	},
	"MS14-056": {
		"Internet Explorer 6":  {"CVE-2014-4123", "CVE-2014-4124", "CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4138", "CVE-2014-4140", "CVE-2014-4141"},
		"Internet Explorer 7":  {"CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4138", "CVE-2014-4140", "CVE-2014-4141"},
		"Internet Explorer 8":  {"CVE-2014-4126", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4137", "CVE-2014-4138", "CVE-2014-4140"},
		"Internet Explorer 9":  {"CVE-2014-4126", "CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137", "CVE-2014-4138"},
		"Internet Explorer 10": {"CVE-2014-4129", "CVE-2014-4130", "CVE-2014-4132", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137", "CVE-2014-4138"},
		"Internet Explorer 11": {"CVE-2014-4127", "CVE-2014-4129", "CVE-2014-4133", "CVE-2014-4134", "CVE-2014-4137"},
	},
	"MS14-065": {
		"Internet Explorer 6":  {"CVE-2014-6323", "CVE-2014-6337", "CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6346", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350", "CVE-2014-6351"},
		"Internet Explorer 7":  {"CVE-2014-6337", "CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6346", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350", "CVE-2014-6351"},
		"Internet Explorer 8":  {"CVE-2014-6337", "CVE-2014-6342", "CVE-2014-6343", "CVE-2014-6345", "CVE-2014-6347", "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350"},
		"Internet Explorer 9":  {"CVE-2014-6337", "CVE-2014-6347", "CVE-2014-6349", "CVE-2014-6350"},
		"Internet Explorer 10": {"CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6344", "CVE-2014-6347", "CVE-2014-6348"},
		"Internet Explorer 11": {"CVE-2014-6339", "CVE-2014-6342", "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6348", "CVE-2014-6353"},
	},
	"MS14-080": {
		"Internet Explorer 6":  {"CVE-2014-6327", "CVE-2014-6328", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6365", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376"},
		"Internet Explorer 7":  {"CVE-2014-6327", "CVE-2014-6328", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6365", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376"},
		"Internet Explorer 8":  {"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6363", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6369", "CVE-2014-6373", "CVE-2014-6376"},
		"Internet Explorer 9":  {"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-6376", "CVE-2014-8966"},
		"Internet Explorer 10": {"CVE-2014-6327", "CVE-2014-6329", "CVE-2014-6330", "CVE-2014-6366", "CVE-2014-6368", "CVE-2014-6375", "CVE-2014-6376", "CVE-2014-8966"},
		"Internet Explorer 11": {"CVE-2014-6330", "CVE-2014-6366", "CVE-2014-6373", "CVE-2014-6375", "CVE-2014-8966"},
	},
	"MS15-009": {
		"Internet Explorer 6":  {"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0043", "CVE-2015-0044", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0054", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"},
		"Internet Explorer 7":  {"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0043", "CVE-2015-0044", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"},
		"Internet Explorer 8":  {"CVE-2015-0018", "CVE-2015-0019", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0028", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0038", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0042", "CVE-2015-0046", "CVE-2015-0048", "CVE-2015-0052", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069", "CVE-2015-0071"},
		"Internet Explorer 9":  {"CVE-2015-0018", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0027", "CVE-2015-0029", "CVE-2015-0035", "CVE-2015-0037", "CVE-2015-0039", "CVE-2015-0040", "CVE-2015-0045", "CVE-2015-0049", "CVE-2015-0051", "CVE-2015-0052", "CVE-2015-0053", "CVE-2015-0055", "CVE-2015-0066", "CVE-2015-0068", "CVE-2015-0069"},
		"Internet Explorer 10": {"CVE-2014-8967", "CVE-2015-0018", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0037", "CVE-2015-0040", "CVE-2015-0044", "CVE-2015-0045", "CVE-2015-0048", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0053", "CVE-2015-0066", "CVE-2015-0067"},
		"Internet Explorer 11": {"CVE-2014-8967", "CVE-2015-0019", "CVE-2015-0021", "CVE-2015-0023", "CVE-2015-0025", "CVE-2015-0028", "CVE-2015-0029", "CVE-2015-0044", "CVE-2015-0045", "CVE-2015-0048", "CVE-2015-0049", "CVE-2015-0050", "CVE-2015-0051", "CVE-2015-0053", "CVE-2015-0067"},
	},
	"MS15-018": {
		"Internet Explorer 6":  {"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1626", "CVE-2015-1627"},
		"Internet Explorer 7":  {"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1626"},
		"Internet Explorer 8":  {"CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1626"},
		"Internet Explorer 9":  {"CVE-2015-0056", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1626"},
		"Internet Explorer 10": {"CVE-2015-0056", "CVE-2015-0100", "CVE-2015-1623", "CVE-2015-1626"},
		"Internet Explorer 11": {"CVE-2015-0099", "CVE-2015-0100"},
	},
	"MS15-032": {
		"Internet Explorer 6":  {"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1667", "CVE-2015-1668"},
		"Internet Explorer 7":  {"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1667", "CVE-2015-1668"},
		"Internet Explorer 8":  {"CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1668"},
		"Internet Explorer 9":  {"CVE-2015-1659", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1668"},
		"Internet Explorer 10": {"CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1662", "CVE-2015-1665"},
		"Internet Explorer 11": {"CVE-2015-1660"},
	},
	"MS15-043": {
		"Internet Explorer 6":  {"CVE-2015-1658", "CVE-2015-1684", "CVE-2015-1685", "CVE-2015-1686", "CVE-2015-1688", "CVE-2015-1689", "CVE-2015-1691", "CVE-2015-1692", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1709", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"},
		"Internet Explorer 7":  {"CVE-2015-1658", "CVE-2015-1684", "CVE-2015-1685", "CVE-2015-1686", "CVE-2015-1689", "CVE-2015-1691", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1709", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"},
		"Internet Explorer 8":  {"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1689", "CVE-2015-1705", "CVE-2015-1706", "CVE-2015-1711", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"},
		"Internet Explorer 9":  {"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1706", "CVE-2015-1711", "CVE-2015-1713", "CVE-2015-1714", "CVE-2015-1717", "CVE-2015-1718"},
		"Internet Explorer 10": {"CVE-2015-1658", "CVE-2015-1685", "CVE-2015-1691", "CVE-2015-1706", "CVE-2015-1708", "CVE-2015-1711", "CVE-2015-1712", "CVE-2015-1713", "CVE-2015-1717", "CVE-2015-1718"},
		"Internet Explorer 11": {"CVE-2015-1691", "CVE-2015-1708", "CVE-2015-1712"},
	},
	"MS15-056": {
		"Internet Explorer 6":  {"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1743", "CVE-2015-1747", "CVE-2015-1748", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755", "CVE-2015-1765"},
		"Internet Explorer 7":  {"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755", "CVE-2015-1765"},
		"Internet Explorer 8":  {"CVE-2015-1730", "CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1741", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1752", "CVE-2015-1753", "CVE-2015-1755", "CVE-2015-1765"},
		"Internet Explorer 9":  {"CVE-2015-1731", "CVE-2015-1732", "CVE-2015-1736", "CVE-2015-1737", "CVE-2015-1739", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1751", "CVE-2015-1753", "CVE-2015-1754", "CVE-2015-1755"},
		"Internet Explorer 10": {"CVE-2015-1687", "CVE-2015-1730", "CVE-2015-1732", "CVE-2015-1742", "CVE-2015-1747", "CVE-2015-1750", "CVE-2015-1753", "CVE-2015-1754"},
		"Internet Explorer 11": {"CVE-2015-1687", "CVE-2015-1730", "CVE-2015-1751", "CVE-2015-1754"},
	},
	"MS15-065": {
		"Internet Explorer 6":  {"CVE-2015-1729", "CVE-2015-1733", "CVE-2015-1738", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2398", "CVE-2015-2401", "CVE-2015-2402", "CVE-2015-2403", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2414", "CVE-2015-2419", "CVE-2015-2425"},
		"Internet Explorer 7":  {"CVE-2015-1729", "CVE-2015-1733", "CVE-2015-1738", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2398", "CVE-2015-2401", "CVE-2015-2403", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2414", "CVE-2015-2419", "CVE-2015-2425"},
		"Internet Explorer 8":  {"CVE-2015-1729", "CVE-2015-1767", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2389", "CVE-2015-2391", "CVE-2015-2401", "CVE-2015-2408", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2419", "CVE-2015-2425"},
		"Internet Explorer 9":  {"CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2389", "CVE-2015-2403", "CVE-2015-2411", "CVE-2015-2412", "CVE-2015-2419", "CVE-2015-2425"},
		"Internet Explorer 10": {"CVE-2015-1738", "CVE-2015-2383", "CVE-2015-2384", "CVE-2015-2388", "CVE-2015-2391", "CVE-2015-2403", "CVE-2015-2425"},
		"Internet Explorer 11": {"CVE-2015-1738", "CVE-2015-2388", "CVE-2015-2391", "CVE-2015-2403"},
	},
	"MS15-079": {
		"Internet Explorer 7":                {"CVE-2015-2442", "CVE-2015-2443", "CVE-2015-2444", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451"},
		"Internet Explorer 8":                {"CVE-2015-2443", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451"},
		"Internet Explorer 9":                {"CVE-2015-2443", "CVE-2015-2445", "CVE-2015-2446", "CVE-2015-2447"},
		"Internet Explorer 10":               {"CVE-2015-2446", "CVE-2015-2447"},
		"Internet Explorer 11":               {"CVE-2015-2445", "CVE-2015-2448"},
		"Internet Explorer 11 on Windows 10": {"CVE-2015-2443", "CVE-2015-2444", "CVE-2015-2445", "CVE-2015-2447", "CVE-2015-2448", "CVE-2015-2450", "CVE-2015-2451", "CVE-2015-2452"},
	},
	"MS15-094": {
		"Internet Explorer 7":                {"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2489", "CVE-2015-2491", "CVE-2015-2493", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"},
		"Internet Explorer 8":                {"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2489", "CVE-2015-2491", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"},
		"Internet Explorer 9":                {"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2489", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2542"},
		"Internet Explorer 10":               {"CVE-2015-2489", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501"},
		"Internet Explorer 11":               {"CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501"},
		"Internet Explorer 11 on Windows 10": {"CVE-2015-2483", "CVE-2015-2487", "CVE-2015-2490", "CVE-2015-2491", "CVE-2015-2493", "CVE-2015-2500", "CVE-2015-2501", "CVE-2015-2541"},
	},
	"MS15-097": {
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows 8 for 32-bit Systems":                                                           {"CVE-2015-2529"},
		"Windows 8 for x64-based Systems":                                                        {"CVE-2015-2529"},
		"Windows RT":                                                                             {"CVE-2015-2529"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                                  {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":       {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                           {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                               {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)":    {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Server 2012":                                                                    {"CVE-2015-2529"},
		"Windows Server 2012 (Server Core installation)":                                         {"CVE-2015-2529"},
		"Windows Vista Service Pack 2":                                                           {"CVE-2015-2527", "CVE-2015-2529"},
		"Windows Vista x64 Edition Service Pack 2":                                               {"CVE-2015-2527", "CVE-2015-2529"},
	},
	"MS15-106": {
		"Internet Explorer 7":                {"CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6047", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055", "CVE-2015-6056", "CVE-2015-6059"},
		"Internet Explorer 8":                {"CVE-2015-6042", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6053", "CVE-2015-6056"},
		"Internet Explorer 9":                {"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6053"},
		"Internet Explorer 10":               {"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6053"},
		"Internet Explorer 11":               {"CVE-2015-6044", "CVE-2015-6050"},
		"Internet Explorer 11 on Windows 10": {"CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6048", "CVE-2015-6050", "CVE-2015-6051"},
	},
	"MS15-112": {
		"Internet Explorer 7":                {"CVE-2015-2427", "CVE-2015-6064", "CVE-2015-6065", "CVE-2015-6068", "CVE-2015-6069", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6078", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6081", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085", "CVE-2015-6086", "CVE-2015-6088", "CVE-2015-6089"},
		"Internet Explorer 8":                {"CVE-2015-2427", "CVE-2015-6064", "CVE-2015-6065", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6078", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085", "CVE-2015-6086", "CVE-2015-6088"},
		"Internet Explorer 9":                {"CVE-2015-6064", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082", "CVE-2015-6084", "CVE-2015-6085"},
		"Internet Explorer 10":               {"CVE-2015-2427", "CVE-2015-6068", "CVE-2015-6072", "CVE-2015-6073", "CVE-2015-6075", "CVE-2015-6077", "CVE-2015-6079", "CVE-2015-6080", "CVE-2015-6082"},
		"Internet Explorer 11":               {"CVE-2015-2427"},
		"Internet Explorer 11 on Windows 10": {"CVE-2015-2427", "CVE-2015-6082"},
	},
	"MS15-124": {
		"Internet Explorer 7":                {"CVE-2015-6083", "CVE-2015-6134", "CVE-2015-6135", "CVE-2015-6136", "CVE-2015-6138", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6144", "CVE-2015-6147", "CVE-2015-6148", "CVE-2015-6149", "CVE-2015-6151", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6156", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162", "CVE-2015-6164"},
		"Internet Explorer 8":                {"CVE-2015-6134", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6148", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6156", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162", "CVE-2015-6164"},
		"Internet Explorer 9":                {"CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6152", "CVE-2015-6153", "CVE-2015-6155", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160", "CVE-2015-6162"},
		"Internet Explorer 10":               {"CVE-2015-6134", "CVE-2015-6139", "CVE-2015-6140", "CVE-2015-6141", "CVE-2015-6142", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6153", "CVE-2015-6157", "CVE-2015-6158", "CVE-2015-6159", "CVE-2015-6160"},
		"Internet Explorer 11":               {"CVE-2015-6134", "CVE-2015-6141", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6152", "CVE-2015-6162"},
		"Internet Explorer 11 on Windows 10": {"CVE-2015-6134", "CVE-2015-6141", "CVE-2015-6143", "CVE-2015-6145", "CVE-2015-6146", "CVE-2015-6147", "CVE-2015-6149", "CVE-2015-6150", "CVE-2015-6152", "CVE-2015-6162", "CVE-2015-6164"},
	},
	"MS15-128": {
		"Windows 7 for 32-bit Systems Service Pack 1":                     {"CVE-2015-6106"},
		"Windows 7 for x64-based Systems Service Pack 1":                  {"CVE-2015-6106"},
		"Windows 8 for 32-bit Systems":                                    {"CVE-2015-6106"},
		"Windows 8 for x64-based Systems":                                 {"CVE-2015-6106"},
		"Windows 8.1 for 32-bit Systems":                                  {"CVE-2015-6106"},
		"Windows 8.1 for x64-based Systems":                               {"CVE-2015-6106"},
		"Windows RT":                                                      {"CVE-2015-6106"},
		"Windows RT 8.1":                                                  {"CVE-2015-6106"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1": {"CVE-2015-6106"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":     {"CVE-2015-6106"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2015-6106"},
		"Windows Server 2012":                               {"CVE-2015-6106"},
		"Windows Server 2012 (Server Core installation)":    {"CVE-2015-6106"},
		"Windows Server 2012 R2":                            {"CVE-2015-6106"},
		"Windows Server 2012 R2 (Server Core installation)": {"CVE-2015-6106"},
	},
	"MS16-001": {
		"Internet Explorer 7": {"CVE-2016-0002", "CVE-2016-0005"},
		"Internet Explorer 8": {"CVE-2016-0005"},
	},
	"MS16-009": {
		"Internet Explorer 9":                {"CVE-2016-0041", "CVE-2016-0062", "CVE-2016-0064"},
		"Internet Explorer 10":               {"CVE-2016-0062", "CVE-2016-0071"},
		"Internet Explorer 11":               {"CVE-2016-0064", "CVE-2016-0071"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-0064", "CVE-2016-0071"},
	},
	"MS16-014": {
		"Windows 8.1 for 32-bit Systems":                        {"CVE-2016-0040", "CVE-2016-0049"},
		"Windows 8.1 for x64-based Systems":                     {"CVE-2016-0040", "CVE-2016-0049"},
		"Windows RT 8.1":                                        {"CVE-2016-0040", "CVE-2016-0049"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2": {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":    {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                        {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                            {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)": {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Server 2012":                               {"CVE-2016-0040"},
		"Windows Server 2012 (Server Core installation)":    {"CVE-2016-0040"},
		"Windows Server 2012 R2":                            {"CVE-2016-0040", "CVE-2016-0049"},
		"Windows Server 2012 R2 (Server Core installation)": {"CVE-2016-0040", "CVE-2016-0049"},
		"Windows Vista Service Pack 2":                      {"CVE-2016-0042", "CVE-2016-0049"},
		"Windows Vista x64 Edition Service Pack 2":          {"CVE-2016-0042", "CVE-2016-0049"},
	},
	"MS16-015": {
		"Microsoft Excel 2016 for Mac": {"CVE-2016-0022", "CVE-2016-0052"},
		"Microsoft Excel for Mac 2011": {"CVE-2016-0022", "CVE-2016-0052"},
		"Microsoft Word 2016 for Mac":  {"CVE-2016-0054"},
		"Microsoft Word for Mac 2011":  {"CVE-2016-0054"},
	},
	"MS16-023": {
		"Internet Explorer 9":                {"CVE-2016-0102", "CVE-2016-0103", "CVE-2016-0104", "CVE-2016-0106", "CVE-2016-0108", "CVE-2016-0109", "CVE-2016-0110", "CVE-2016-0114"},
		"Internet Explorer 10":               {"CVE-2016-0102", "CVE-2016-0103", "CVE-2016-0106", "CVE-2016-0108", "CVE-2016-0109", "CVE-2016-0114"},
		"Internet Explorer 11":               {"CVE-2016-0104"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-0103", "CVE-2016-0104", "CVE-2016-0106", "CVE-2016-0113", "CVE-2016-0114"},
	},
	"MS16-037": {
		"Internet Explorer 9":                {"CVE-2016-0160", "CVE-2016-0164", "CVE-2016-0166"},
		"Internet Explorer 10":               {"CVE-2016-0159", "CVE-2016-0160", "CVE-2016-0166"},
		"Internet Explorer 11":               {"CVE-2016-0159"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-0159", "CVE-2016-0164"},
	},
	"MS16-045": {
		"Windows Server 2012":                            {"CVE-2016-0090"},
		"Windows Server 2012 (Server Core installation)": {"CVE-2016-0090"},
	},
	"MS16-051": {
		"Internet Explorer 9":  {"CVE-2016-0188", "CVE-2016-0194"},
		"Internet Explorer 10": {"CVE-2016-0188"},
		"Internet Explorer 11": {"CVE-2016-0188"},
	},
	"MS16-062": {
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                               {"CVE-2016-0176"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":    {"CVE-2016-0176"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                        {"CVE-2016-0176"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                            {"CVE-2016-0176"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)": {"CVE-2016-0176"},
		"Windows Vista Service Pack 2":                                                        {"CVE-2016-0176"},
		"Windows Vista x64 Edition Service Pack 2":                                            {"CVE-2016-0176"},
	},
	"MS16-063": {
		"Internet Explorer 9":  {"CVE-2016-3202", "CVE-2016-3210"},
		"Internet Explorer 10": {"CVE-2016-3210"},
	},
	"MS16-067": {
		"Windows 8.1 for 32-bit Systems":    {"CVE-2016-0190"},
		"Windows 8.1 for x64-based Systems": {"CVE-2016-0190"},
		"Windows RT 8.1":                    {"CVE-2016-0190"},
	},
	"MS16-084": {
		"Internet Explorer 9":                {"CVE-2016-3243", "CVE-2016-3260", "CVE-2016-3261", "CVE-2016-3277"},
		"Internet Explorer 10":               {"CVE-2016-3260", "CVE-2016-3261"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-3245"},
	},
	"MS16-088": {
		"Microsoft Excel 2016 for Mac": {"CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282"},
		"Microsoft Excel for Mac 2011": {"CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282"},
		"Microsoft Word 2016 for Mac":  {"CVE-2016-3284"},
		"Microsoft Word for Mac 2011":  {"CVE-2016-3284"},
	},
	"MS16-090": {
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2016-3250"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2016-3250"},
		"Windows 8.1 for 32-bit Systems":                                                         {"CVE-2016-3250"},
		"Windows 8.1 for x64-based Systems":                                                      {"CVE-2016-3250"},
		"Windows RT 8.1":                                                                         {"CVE-2016-3250"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2016-3250"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2016-3250"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2016-3250"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                                  {"CVE-2016-3250"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":       {"CVE-2016-3250"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                           {"CVE-2016-3250"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                               {"CVE-2016-3250"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)":    {"CVE-2016-3250"},
		"Windows Server 2012 R2":                                                                 {"CVE-2016-3250"},
		"Windows Server 2012 R2 (Server Core installation)":                                      {"CVE-2016-3250"},
		"Windows Vista Service Pack 2":                                                           {"CVE-2016-3250"},
		"Windows Vista x64 Edition Service Pack 2":                                               {"CVE-2016-3250"},
	},
	"MS16-095": {
		"Internet Explorer 9":  {"CVE-2016-3288", "CVE-2016-3289", "CVE-2016-3290", "CVE-2016-3321", "CVE-2016-3322"},
		"Internet Explorer 10": {"CVE-2016-3288", "CVE-2016-3289", "CVE-2016-3290", "CVE-2016-3322"},
	},
	"MS16-097": {
		"Windows 8.1 for 32-bit Systems":                    {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows 8.1 for x64-based Systems":                 {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows RT 8.1":                                    {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows Server 2012":                               {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows Server 2012 (Server Core installation)":    {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows Server 2012 R2":                            {"CVE-2016-3303", "CVE-2016-3304"},
		"Windows Server 2012 R2 (Server Core installation)": {"CVE-2016-3303", "CVE-2016-3304"},
	},
	"MS16-099": {
		"Microsoft OneNote 2016 for Mac": {"CVE-2016-3313", "CVE-2016-3316", "CVE-2016-3317"},
		"Microsoft Word 2016 for Mac":    {"CVE-2016-3315"},
	},
	"MS16-104": {
		"Internet Explorer 9":  {"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3292", "CVE-2016-3295", "CVE-2016-3325"},
		"Internet Explorer 10": {"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3325"},
		"Internet Explorer 11": {"CVE-2016-3325"},
	},
	"MS16-106": {
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2016-3349"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2016-3349"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2016-3349"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2016-3349"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2016-3349"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2":                                  {"CVE-2016-3349"},
		"Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)":       {"CVE-2016-3349"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2":                           {"CVE-2016-3349"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":                               {"CVE-2016-3349"},
		"Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)":    {"CVE-2016-3349"},
		"Windows Vista Service Pack 2":                                                           {"CVE-2016-3349"},
		"Windows Vista x64 Edition Service Pack 2":                                               {"CVE-2016-3349"},
	},
	"MS16-107": {
		"Microsoft Excel 2016 for Mac":                           {"CVE-2016-3357", "CVE-2016-3360", "CVE-2016-3366"},
		"Microsoft Office 2013 RT Service Pack 1":                {"CVE-2016-0137", "CVE-2016-0141"},
		"Microsoft Office 2013 Service Pack 1 (32-bit editions)": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"},
		"Microsoft Office 2013 Service Pack 1 (64-bit editions)": {"CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357"},
		"Microsoft Outlook 2016 for Mac":                         {"CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3360"},
		"Microsoft PowerPoint 2016 for Mac":                      {"CVE-2016-3357", "CVE-2016-3358", "CVE-2016-3366"},
		"Microsoft Word 2016 for Mac":                            {"CVE-2016-3358", "CVE-2016-3360", "CVE-2016-3366"},
	},
	"MS16-108": {
		"Microsoft Exchange Server 2013 Cumulative Update 12": {"CVE-2016-3379"},
		"Microsoft Exchange Server 2013 Cumulative Update 13": {"CVE-2016-3379"},
		"Microsoft Exchange Server 2013 Service Pack 1":       {"CVE-2016-3379"},
	},
	"MS16-111": {
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2016-3372"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2016-3372"},
		"Windows 8.1 for 32-bit Systems":                                                         {"CVE-2016-3372"},
		"Windows 8.1 for x64-based Systems":                                                      {"CVE-2016-3372"},
		"Windows RT 8.1":                                                                         {"CVE-2016-3372"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1":                        {"CVE-2016-3372"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":                            {"CVE-2016-3372"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2016-3372"},
		"Windows Server 2012":                                                                    {"CVE-2016-3372"},
		"Windows Server 2012 (Server Core installation)":                                         {"CVE-2016-3372"},
		"Windows Server 2012 R2":                                                                 {"CVE-2016-3372"},
		"Windows Server 2012 R2 (Server Core installation)":                                      {"CVE-2016-3372"},
	},
	"MS16-118": {
		"Internet Explorer 9":                {"CVE-2016-3331", "CVE-2016-3383", "CVE-2016-3387", "CVE-2016-3388", "CVE-2016-3390"},
		"Internet Explorer 10":               {"CVE-2016-3331", "CVE-2016-3390"},
		"Internet Explorer 11":               {"CVE-2016-3331"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-3383"},
	},
	"MS16-133": {
		"Microsoft Excel 2016 for Mac": {"CVE-2016-7234"},
		"Microsoft Excel for Mac 2011": {"CVE-2016-7232"},
		"Microsoft Word 2016 for Mac":  {"CVE-2016-7236"},
		"Microsoft Word for Mac 2011":  {"CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7236"},
	},
	"MS16-135": {
		"Windows Server 2008 for 32-bit Systems Service Pack 2":        {"CVE-2016-7255"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2": {"CVE-2016-7255"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":     {"CVE-2016-7255"},
		"Windows Vista Service Pack 2":                                 {"CVE-2016-7255"},
		"Windows Vista x64 Edition Service Pack 2":                     {"CVE-2016-7255"},
	},
	"MS16-142": {
		"Internet Explorer 9":  {"CVE-2016-7196", "CVE-2016-7241"},
		"Internet Explorer 10": {"CVE-2016-7241"},
	},
	"MS16-144": {
		"Internet Explorer 9":                {"CVE-2016-7281", "CVE-2016-7284", "CVE-2016-7287"},
		"Internet Explorer 10":               {"CVE-2016-7287"},
		"Internet Explorer 11 on Windows 10": {"CVE-2016-7278", "CVE-2016-7284"},
	},
	"MS16-148": {
		"Microsoft Excel 2016 for Mac":           {"CVE-2016-7257", "CVE-2016-7274"},
		"Microsoft Excel for Mac 2011":           {"CVE-2016-7268"},
		"Microsoft Office 2016 (32-bit edition)": {"CVE-2016-7275", "CVE-2016-7277"},
		"Microsoft Office 2016 (64-bit edition)": {"CVE-2016-7275", "CVE-2016-7277"},
		"Microsoft Office for Mac 2011":          {"CVE-2016-7290", "CVE-2016-7291"},
		"Microsoft Word for Mac 2011":            {"CVE-2016-7257", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7274", "CVE-2016-7276"},
	},
	"MS17-006": {
		"Internet Explorer 9":  {"CVE-2017-0012", "CVE-2017-0018", "CVE-2017-0033", "CVE-2017-0037", "CVE-2017-0049", "CVE-2017-0154"},
		"Internet Explorer 10": {"CVE-2017-0012", "CVE-2017-0033", "CVE-2017-0049", "CVE-2017-0154"},
		"Internet Explorer 11": {"CVE-2017-0154"},
	},
	"MS17-012": {
		"Windows 10 Version 1607 for 32-bit Systems":                                             {"CVE-2017-0104"},
		"Windows 10 Version 1607 for x64-based Systems":                                          {"CVE-2017-0104"},
		"Windows 7 for 32-bit Systems Service Pack 1":                                            {"CVE-2017-0104"},
		"Windows 7 for x64-based Systems Service Pack 1":                                         {"CVE-2017-0104"},
		"Windows 8.1 for 32-bit Systems":                                                         {"CVE-2017-0104"},
		"Windows 8.1 for x64-based Systems":                                                      {"CVE-2017-0104"},
		"Windows RT 8.1":                                                                         {"CVE-2017-0104"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": {"CVE-2017-0104"},
	},
	"MS17-013": {
		"Windows Server 2008 for 32-bit Systems Service Pack 2":        {"CVE-2017-0038"},
		"Windows Server 2008 for Itanium-based Systems Service Pack 2": {"CVE-2017-0038"},
		"Windows Server 2008 for x64-based Systems Service Pack 2":     {"CVE-2017-0038"},
		"Windows Server 2012 (Server Core installation)":               {"CVE-2017-0063"},
		"Windows Server 2016 for x64-based Systems":                    {"CVE-2017-0038"},
		"Windows Vista Service Pack 2":                                 {"CVE-2017-0038"},
		"Windows Vista x64 Edition Service Pack 2":                     {"CVE-2017-0038"},
	},
	"MS17-017": {
		"Windows 7 for x64-based Systems Service Pack 1":                  {"CVE-2017-0101"},
		"Windows Server 2008 R2 for Itanium-based Systems Service Pack 1": {"CVE-2017-0101"},
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":     {"CVE-2017-0101"},
	},
	"MS17-018": {
		"Windows Server 2016 for x64-based Systems":                            {"CVE-2017-0078"},
		"Windows Server 2016 for x64-based Systems (Server Core installation)": {"CVE-2017-0024", "CVE-2017-0026", "CVE-2017-0078"},
	},
}

// bulletinArchiveCVECorrections maps per-bulletin BulletinSearch.xlsx CVE
// tokens that do not appear in the bulletin's archive markdown to a
// correction action. Source: full set difference of (xlsx cves cell tokens)
// − (CVE-YYYY-NNNN regex hits in the bulletin's archive markdown body),
// across the entire 1554-bulletin corpus.
//
// Each entry is one of two actions:
//   - non-empty fix: replace the bad xlsx token with the named correct CVE.
//     Used when the markdown identifies the real CVE the xlsx token typo'd
//     into AND that real CVE is absent from the xlsx cves cell — so a plain
//     drop would lose the attribution entirely.
//   - empty fix:     drop the bad xlsx token. Used when (a) the candidate
//     real CVE is already present in the xlsx cell (drop is sufficient,
//     attribution preserved), (b) no plausible candidate exists, or (c) the
//     bulletin formally retracted the CVE (e.g. MS16-084 / V1.1).
//
// The three xlsx-side typo patterns observed:
//   - Year-shift  : CVE-2006-4131 → CVE-2005-4131 (MS06-012)
//   - Off-by-one  : CVE-2011-3403 → CVE-2011-3404 (MS11-099)
//   - Leading 0   : CVE-2017-00016 → CVE-2017-0016 (MS17-012)
var bulletinArchiveCVECorrections = map[string]map[string]string{
	// MS06-012: year-typo of CVE-2005-4131 ("Excel eBay Vulnerability") —
	// remap (CVE-2005-4131 not in xlsx).
	"MS06-012": {"CVE-2006-4131": "CVE-2005-4131"},
	// MS06-021: CVE-2006-4089 is a year-typo of CVE-2005-4089 ("CSS
	// Cross-Domain Information Disclosure") — remap (CVE-2005-4089 not in
	// xlsx). CVE-2006-2283 has no candidate in MS06-021's markdown — drop.
	"MS06-021": {"CVE-2006-2283": "", "CVE-2006-4089": "CVE-2005-4089"},
	// (MS08-032 / CVE-2007-0675 omitted: the archive markdown at
	// ms08-032.md is mis-mapped — its content is actually MS16-011's — so
	// the absence-in-markdown signal cannot distinguish typo from real
	// attribution. CVE-2007-0675 is a real ActiveX vulnerability addressed
	// by the MS08-032 Cumulative ActiveX Kill Bit update.)
	// MS11-056: off-by-one of CVE-2011-1284 — remap (1284 not in xlsx).
	"MS11-056": {"CVE-2011-1285": "CVE-2011-1284"},
	// MS11-099: off-by-one of CVE-2011-3404 — remap (3404 not in xlsx).
	// CVE-2011-3403 itself appears in MS11-096's markdown.
	"MS11-099": {"CVE-2011-3403": "CVE-2011-3404"},
	// MS13-028: no candidate in markdown — drop both.
	"MS13-028": {"CVE-2013-2013": "", "CVE-2013-2014": ""},
	// MS13-037: off-by-one of CVE-2013-1312 — drop, 1312 already in xlsx.
	// CVE-2013-1313 appears in MS13-020's markdown.
	"MS13-037": {"CVE-2013-1313": ""},
	// MS13-059: off-by-3 of CVE-2013-3184 — drop, 3184 already in xlsx.
	// CVE-2013-3181 appears in MS13-060's markdown.
	"MS13-059": {"CVE-2013-3181": ""},
	// MS14-051: off-by-3 of CVE-2014-2796 — drop, 2796 already in xlsx.
	// CVE-2014-2799 appears in MS14-052's markdown.
	"MS14-051": {"CVE-2014-2799": ""},
	// MS15-036: 5-digit suffix anomaly; no clean canonical-form candidate —
	// drop.
	"MS15-036": {"CVE-2015-16453": ""},
	// MS15-048: 5-digit suffix anomaly; no clean canonical-form candidate —
	// drop.
	"MS15-048": {"CVE-2015-16723": ""},
	// MS16-003: off-by-one of CVE-2016-0002 — remap (0002 not in xlsx).
	// CVE-2016-0003 appears in MS16-002's markdown.
	"MS16-003": {"CVE-2016-0003": "CVE-2016-0002"},
	// MS16-079: cross-year mis-tag of CVE-2015-6015 — remap (6015 not in
	// xlsx). CVE-2015-6016 not in any MS16 bulletin.
	"MS16-079": {"CVE-2015-6016": "CVE-2015-6015"},
	// MS16-084: Microsoft retracted CVE-2016-3276 in the V1.1 (2017-03-17)
	// revision — "Removed CVE-2016-3276 ... because IE 9/10/11 are not
	// affected." Drop, no correction.
	"MS16-084": {"CVE-2016-3276": ""},
	// MS16-144: no candidate in markdown — drop.
	"MS16-144": {"CVE-2016-7293": ""},
	// MS17-012: leading-zero typo of CVE-2017-0016 — remap (0016 not in
	// xlsx; the xlsx cell carries "CVE-2017-00016" with an extra zero).
	"MS17-012": {"CVE-2017-00016": "CVE-2017-0016"},
}

// bulletinArchiveCVEAdditions fills in CVE tokens that BulletinSearch.xlsx
// leaves off a bulletin's rows but the bulletin's archive markdown documents.
// Two related cases:
//
//   - xlsx all-empty: Microsoft published the bulletin without populating the
//     xlsx cves cell at all (every row of the bulletin is empty). The markdown
//     then carries the authoritative CVE list.
//   - xlsx partial: xlsx carries some CVEs but the markdown documents additional
//     ones the xlsx omits. Markdown-side typos / cross-references that surface
//     in a naive harvest are filtered out via a per-(bulletin, CVE) skip-list
//     curated by manual review. The skip-list and the per-bulletin CVE
//     harvest live in a local generator script outside this repo; this
//     map is the committed snapshot of the generator's output.
//
// At extract time the listed CVEs are unioned into row.CVEs for every row of the
// bulletin (idempotent if the xlsx already happens to carry the CVE). The map holds
// only curated CVE tokens: the authoritative markdown list for all-empty bulletins,
// and the post-review harvest for partial-xlsx bulletins. Per-(KB, CVE) applicability
// continues to be enforced by bulletinArchiveKBNotApplicable after the union; the NA
// filter drops per-row entries that the matrix table marks Not applicable.
//
// Symmetric to bulletinArchiveCVECorrections, which fixes wrong tokens already
// present in the xlsx (typo / drop), this map adds tokens that the xlsx omits.
var bulletinArchiveCVEAdditions = map[string][]string{
	"MS02-019": {"CVE-2002-0153"},
	"MS02-038": {"CVE-2002-0644", "CVE-2002-0645"},
	"MS06-007": {"CVE-2006-0021"},
	"MS06-015": {"CVE-2004-2289", "CVE-2006-0012"},
	"MS06-021": {"CVE-2005-4089", "CVE-2006-1303", "CVE-2006-1626", "CVE-2006-1992", "CVE-2006-2218", "CVE-2006-2382", "CVE-2006-2383", "CVE-2006-2384", "CVE-2006-2385"},
	"MS06-039": {"CVE-2006-0007", "CVE-2006-0033"},
	"MS07-002": {"CVE-2007-0027", "CVE-2007-0028", "CVE-2007-0029", "CVE-2007-0030", "CVE-2007-0031"},
	"MS07-039": {"CVE-2007-0040", "CVE-2007-3028"},
	// MS07-040 includes CVE-2006-7192 because the bulletin's V1.0
	// note states the update "includes a defense-in-depth change
	// to ASP.NET ... mitigates the issue ... CVE-2006-7192".
	// Mitigation rather than full fix, but the KB is the only
	// vehicle delivering the protection.
	"MS07-040": {"CVE-2006-7192", "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043"},
	"MS07-045": {"CVE-2007-0943", "CVE-2007-1891", "CVE-2007-1892", "CVE-2007-2216", "CVE-2007-3041"},
	"MS07-069": {"CVE-2007-3902", "CVE-2007-3903", "CVE-2007-5344", "CVE-2007-5347"},
	"MS08-028": {"CVE-2005-0944", "CVE-2007-6026"},
	"MS08-029": {"CVE-2008-1437", "CVE-2008-1438"},
	"MS08-038": {"CVE-2008-0951", "CVE-2008-1435"},
	"MS08-058": {"CVE-2008-2947", "CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476"},
	"MS08-059": {"CVE-2008-3466"},
	"MS09-020": {"CVE-2009-1122", "CVE-2009-1535", "CVE-2009-1676"},
	"MS09-072": {"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3672", "CVE-2009-3673", "CVE-2009-3674"},
	"MS11-050": {"CVE-2011-1246", "CVE-2011-1250", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258", "CVE-2011-1260", "CVE-2011-1261", "CVE-2011-1262", "CVE-2011-1346"},
	// MS11-057 includes CVE-2011-1347 because the bulletin's update
	// FAQ states "this update addresses a Protected Mode bypass
	// issue, publicly disclosed". The CVE is not in the main
	// vulnerability table but the update explicitly addresses it.
	"MS11-057": {"CVE-2011-1257", "CVE-2011-1347", "CVE-2011-1960", "CVE-2011-1961", "CVE-2011-1962", "CVE-2011-1963", "CVE-2011-1964", "CVE-2011-2383"},
	"MS11-091": {"CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412"},
	"MS11-096": {"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-3403"},
	"MS11-099": {"CVE-2011-1992", "CVE-2011-2019", "CVE-2011-3389", "CVE-2011-3404"},
	"MS11-100": {"CVE-2011-3414", "CVE-2011-3415", "CVE-2011-3416", "CVE-2011-3417", "CVE-2012-0160", "CVE-2012-0161"},
	"MS12-039": {"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858"},
	"MS12-080": {"CVE-2012-3214", "CVE-2012-3217", "CVE-2012-4791"},
	"MS13-028": {"CVE-2013-1303", "CVE-2013-1304", "CVE-2013-1338"},
	"MS13-059": {"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3192", "CVE-2013-3193", "CVE-2013-3194", "CVE-2013-3199"},
	"MS13-063": {"CVE-2013-2556", "CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"},
	"MS13-072": {"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"},
	"MS13-076": {"CVE-2013-1341", "CVE-2013-1342", "CVE-2013-1343", "CVE-2013-1344", "CVE-2013-3864", "CVE-2013-3865", "CVE-2013-3866"},
	"MS14-075": {"CVE-2014-6319", "CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"},
	"MS15-018": {"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1625", "CVE-2015-1626", "CVE-2015-1627", "CVE-2015-1634"},
	"MS15-032": {"CVE-2014-6374", "CVE-2015-1652", "CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1661", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1666", "CVE-2015-1667", "CVE-2015-1668"},
	"MS15-036": {"CVE-2015-1640", "CVE-2015-1653"},
	"MS15-048": {"CVE-2015-1672", "CVE-2015-1673"},
	"MS15-061": {"CVE-2015-1719", "CVE-2015-1720", "CVE-2015-1721", "CVE-2015-1722", "CVE-2015-1723", "CVE-2015-1724", "CVE-2015-1725", "CVE-2015-1726", "CVE-2015-1727", "CVE-2015-1768", "CVE-2015-2360"},
	"MS15-094": {"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2486", "CVE-2015-2487", "CVE-2015-2489", "CVE-2015-2490", "CVE-2015-2491", "CVE-2015-2492", "CVE-2015-2493", "CVE-2015-2494", "CVE-2015-2496", "CVE-2015-2498", "CVE-2015-2499", "CVE-2015-2500", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"},
	"MS15-099": {"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2522", "CVE-2015-2523", "CVE-2015-2545"},
	"MS15-106": {"CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6047", "CVE-2015-6048", "CVE-2015-6049", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055", "CVE-2015-6056", "CVE-2015-6059", "CVE-2015-6184"},
	"MS15-110": {"CVE-2015-2555", "CVE-2015-2556", "CVE-2015-2557", "CVE-2015-2558", "CVE-2015-6037", "CVE-2015-6039"},
	"MS15-116": {"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"},
	"MS16-002": {"CVE-2016-0003", "CVE-2016-0024"},
	"MS16-004": {"CVE-2015-6117", "CVE-2015-6177", "CVE-2016-0010", "CVE-2016-0011", "CVE-2016-0012", "CVE-2016-0035"},
	"MS16-022": {"CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967", "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971", "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975", "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979", "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983", "CVE-2016-0984", "CVE-2016-0985"},
	"MS16-036": {"CVE-2015-8652", "CVE-2015-8655", "CVE-2015-8658", "CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963", "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989", "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0993", "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-1001", "CVE-2016-1005", "CVE-2016-1010"},
	"MS16-050": {"CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013", "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017", "CVE-2016-1018", "CVE-2016-1019"},
	"MS16-064": {"CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099", "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103", "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107", "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108", "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112", "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116", "CVE-2016-4117"},
	"MS16-077": {"CVE-2016-3213", "CVE-2016-3236", "CVE-2016-3299"},
	"MS16-083": {"CVE-2016-4121", "CVE-2016-4122", "CVE-2016-4123", "CVE-2016-4124", "CVE-2016-4125", "CVE-2016-4126", "CVE-2016-4127", "CVE-2016-4128", "CVE-2016-4129", "CVE-2016-4130", "CVE-2016-4131", "CVE-2016-4132", "CVE-2016-4133", "CVE-2016-4134", "CVE-2016-4135", "CVE-2016-4136", "CVE-2016-4137", "CVE-2016-4138", "CVE-2016-4139", "CVE-2016-4140", "CVE-2016-4141", "CVE-2016-4142", "CVE-2016-4143", "CVE-2016-4144", "CVE-2016-4145", "CVE-2016-4146", "CVE-2016-4147", "CVE-2016-4148", "CVE-2016-4149", "CVE-2016-4150", "CVE-2016-4151", "CVE-2016-4152", "CVE-2016-4153", "CVE-2016-4154", "CVE-2016-4155", "CVE-2016-4156", "CVE-2016-4166", "CVE-2016-4171"},
	"MS16-084": {"CVE-2016-3204", "CVE-2016-3240", "CVE-2016-3241", "CVE-2016-3242", "CVE-2016-3243", "CVE-2016-3245", "CVE-2016-3248", "CVE-2016-3259", "CVE-2016-3260", "CVE-2016-3261", "CVE-2016-3264", "CVE-2016-3273", "CVE-2016-3274", "CVE-2016-3277"},
	"MS16-093": {"CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4182", "CVE-2016-4185", "CVE-2016-4188", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249"},
	"MS16-105": {"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3294", "CVE-2016-3295", "CVE-2016-3297", "CVE-2016-3325", "CVE-2016-3330", "CVE-2016-3350", "CVE-2016-3351", "CVE-2016-3370", "CVE-2016-3374", "CVE-2016-3377"},
	// MS16-108 covers the Oracle Outside In Libraries Vulnerabilities
	// per Oracle Critical Patch Update Advisory - July 2016. The
	// CVEs are listed inline-grouped by severity (RCE / Info
	// Disclosure / DoS) in the bulletin body rather than in per-CVE
	// section headings, which is why the harvester sees them once
	// each in markdown.
	"MS16-108": {"CVE-2015-6014", "CVE-2016-0138", "CVE-2016-3378", "CVE-2016-3379", "CVE-2016-3574", "CVE-2016-3575", "CVE-2016-3576", "CVE-2016-3577", "CVE-2016-3578", "CVE-2016-3579", "CVE-2016-3580", "CVE-2016-3581", "CVE-2016-3582", "CVE-2016-3583", "CVE-2016-3590", "CVE-2016-3591", "CVE-2016-3592", "CVE-2016-3593", "CVE-2016-3594", "CVE-2016-3595", "CVE-2016-3596"},
	"MS16-117": {"CVE-2016-4271", "CVE-2016-4272", "CVE-2016-4274", "CVE-2016-4275", "CVE-2016-4276", "CVE-2016-4277", "CVE-2016-4278", "CVE-2016-4279", "CVE-2016-4280", "CVE-2016-4281", "CVE-2016-4282", "CVE-2016-4283", "CVE-2016-4284", "CVE-2016-4285", "CVE-2016-4287", "CVE-2016-6921", "CVE-2016-6922", "CVE-2016-6923", "CVE-2016-6924", "CVE-2016-6925", "CVE-2016-6926", "CVE-2016-6927", "CVE-2016-6929", "CVE-2016-6930", "CVE-2016-6931", "CVE-2016-6932"},
	"MS16-123": {"CVE-2016-3266", "CVE-2016-3341", "CVE-2016-3376", "CVE-2016-7185", "CVE-2016-7191", "CVE-2016-7211"},
	"MS16-127": {"CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982", "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986", "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992"},
	"MS16-128": {"CVE-2016-7855"},
	"MS16-134": {"CVE-2016-0026", "CVE-2016-3332", "CVE-2016-3333", "CVE-2016-3334", "CVE-2016-3335", "CVE-2016-3338", "CVE-2016-3340", "CVE-2016-3342", "CVE-2016-3343", "CVE-2016-7184"},
	"MS16-137": {"CVE-2016-7220", "CVE-2016-7237", "CVE-2016-7238"},
	"MS16-141": {"CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860", "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864", "CVE-2016-7865"},
	"MS16-148": {"CVE-2016-7257", "CVE-2016-7262", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7268", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7298", "CVE-2016-7300"},
	"MS16-154": {"CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870", "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874", "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878", "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890", "CVE-2016-7892"},
	"MS17-003": {"CVE-2017-2925", "CVE-2017-2926", "CVE-2017-2927", "CVE-2017-2928", "CVE-2017-2930", "CVE-2017-2931", "CVE-2017-2932", "CVE-2017-2933", "CVE-2017-2934", "CVE-2017-2935", "CVE-2017-2936", "CVE-2017-2937"},
	"MS17-005": {"CVE-2017-2982", "CVE-2017-2984", "CVE-2017-2985", "CVE-2017-2986", "CVE-2017-2987", "CVE-2017-2988", "CVE-2017-2990", "CVE-2017-2991", "CVE-2017-2992", "CVE-2017-2993", "CVE-2017-2994", "CVE-2017-2995", "CVE-2017-2996"},
	"MS17-007": {"CVE-2017-0009", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012", "CVE-2017-0015", "CVE-2017-0017", "CVE-2017-0023", "CVE-2017-0032", "CVE-2017-0033", "CVE-2017-0034", "CVE-2017-0035", "CVE-2017-0037", "CVE-2017-0065", "CVE-2017-0066", "CVE-2017-0067", "CVE-2017-0068", "CVE-2017-0069", "CVE-2017-0070", "CVE-2017-0071", "CVE-2017-0094", "CVE-2017-0131", "CVE-2017-0132", "CVE-2017-0133", "CVE-2017-0134", "CVE-2017-0135", "CVE-2017-0136", "CVE-2017-0137", "CVE-2017-0138", "CVE-2017-0140", "CVE-2017-0141", "CVE-2017-0150", "CVE-2017-0151"},
	"MS17-011": {"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0084", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0118", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0121", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"},
	"MS17-017": {"CVE-2017-0050", "CVE-2017-0101", "CVE-2017-0102", "CVE-2017-0103"},
	"MS17-023": {"CVE-2017-2997", "CVE-2017-2998", "CVE-2017-2999", "CVE-2017-3000", "CVE-2017-3001", "CVE-2017-3002", "CVE-2017-3003"},
}
