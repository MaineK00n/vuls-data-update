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
