package bulletin

import (
	"strings"

	bulletin "github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/bulletin"
)

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

// supersedesAdjust amends the supersedes edges for a single KB.
// Add: superseded-by KBs to union into the global kbSupersededBy[KB] set.
// Override: superseded-by KBs that BulletinSearch.xlsx incorrectly
// attributes to this KB and should be removed from kbSupersededBy[KB].
type supersedesAdjust struct {
	Add      []string
	Override []string
}

// bulletinArchiveAmendments is the single source of truth for static
// per-bulletin corrections to the extracted dataset. Entries are added
// incrementally by the migration that consolidates the legacy top-level
// amendment maps; once that migration completes, the legacy maps are
// removed.
var bulletinArchiveAmendments = map[string]bulletinArchiveAmendment{}

// lookupAmendment returns the amendment record for a row's bulletin, or
// the zero value if the bulletin has no amendments. Bulletin IDs are
// matched case-insensitively (markdown filenames and xlsx labels diverge
// in casing for some bulletins).
func lookupAmendment(bulletinID string) bulletinArchiveAmendment {
	return bulletinArchiveAmendments[strings.ToUpper(bulletinID)]
}

// matchesRow reports whether a cveAdjustment's selector matches the given
// row. componentKey is the result of normalizeArchiveComponentKey for the
// row; the caller is expected to compute it once per row and pass it in
// to avoid recomputation across multiple adjustments.
func (a cveAdjustment) matchesRow(row bulletin.Bulletin, componentKey string) bool {
	if a.KB != "" && a.KB != row.ComponentKB {
		return false
	}
	if a.Component != "" && a.Component != componentKey {
		return false
	}
	return true
}
