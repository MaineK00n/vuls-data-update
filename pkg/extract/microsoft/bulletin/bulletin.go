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

// applyCVEAdditions unions per-bulletin CVE tokens from each bulletin's
// bulletinArchiveAmendments record into each row's CVEs string. Used
// for bulletins where BulletinSearch.xlsx left the cves cell empty
// across every row despite the markdown documenting CVE attributions
// (or partially empty — only some xlsx rows carry CVEs). Per-(KB, CVE)
// NA precision is enforced afterwards by bulletinArchiveKBNotApplicable,
// so this map can safely list every CVE the markdown attributes to a
// bulletin.
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
		ad := lookupAmendment(row.BulletinID)
		var adds []string
		for _, adj := range ad.CVEAdjustments {
			if adj.KB == "" && adj.Component == "" && len(adj.Add) > 0 {
				adds = append(adds, adj.Add...)
			}
		}
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
		// bulletinArchiveKBNotApplicable (KB-keyed; below) and the
		// bulletin's bulletinArchiveAmendments record (per-bulletin
		// Component-keyed Drop adjustments). The amendments record also
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

	// Merge supersedes adjustments recovered from each bulletin's archive
	// markdown (https://learn.microsoft.com/en-us/security-updates/securitybulletins/...).
	// Each amendment's Supersedes[oldKB] carries:
	//   - Add: superseded-by KBs to union into kbSupersededBy[oldKB]
	//   - Override: superseded-by KBs that BulletinSearch.xlsx incorrectly
	//     attributes to oldKB and should be removed from kbSupersededBy[oldKB]
	//
	// Same iteration strategy as ieCumChainEdges above: iterate over all
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
		for newKBID, adj := range ad.Supersedes {
			for _, oldKBID := range adj.Override {
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
