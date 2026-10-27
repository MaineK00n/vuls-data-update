package cpecriterion

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
)

type CPE string

// Criterion represents a CPE-only detection criterion.
//   - Vulnerable: a tag for downstream consumers (e.g. to distinguish the
//     vulnerable side from a hardware guard under AND); NOT consulted by
//     Accept (consistent with versioncriterion.Criterion.Accept)
//   - FixStatus: optional fix-state metadata mirroring
//     versioncriterion.Criterion.FixStatus; tag for downstream consumers
//     (e.g. reporting), NOT consulted by Accept
//
// The affected set is described by three contiguous fields — CPE narrows by
// WFN attribute equality, Range narrows by version, and CPEMatches enumerates
// concrete CPEs that fall outside or beyond what Range can express:
//   - CPE: the criterion's canonical CPE string (wildcards permitted)
//   - Range: optional version range narrowing the match (comparator selected
//     by Range.Type — semver / loose version / etc.)
//   - CPEMatches: optional list of concrete CPE strings that the criterion
//     also covers — used for entries that fall OUTSIDE Range (e.g. NVD listed
//     versions that don't satisfy the bounds) or that Range cannot evaluate
//     at all (RangeTypeUnknown / non-parseable versions)
//
// Fixed lives at the end as a separate concern (which versions fix the
// vulnerability), kept off the affected path:
//   - Fixed: optional enumeration of fixed-version strings (scoped to the
//     criterion's CPE — typically extractors partition by product family
//     so the criterion CPE pins vendor/product and Fixed lists only the
//     versions). Mirrors versioncriterion/affected.Affected.Fixed exactly.
//     Carried for remediation reporting on sources (e.g. cisco-csaf) where
//     the fixed set is independent of any affected-range upper bound; NOT
//     consulted by Accept
//
// Detection semantics (see Accept for the full tables):
//
//	(CPE-attr-match AND (
//	    c.version is NA or a pattern             // product only: VU, or Exact for query=ANY (ignores narrowing)
//	    OR (Range==nil AND len(CPEMatches)==0)   // no narrowing
//	    OR query-version is ANY                  // the scan asks for every version
//	    OR query-version is NA                   // no version to evaluate: VU
//	    OR (query-version is concrete AND Range matches)
//	))
//	OR any CPEMatches[i] attr-match              // also tried when main CPE is disjoint
//
// Range is consulted only for a concrete query version. A pattern query
// ("12.*") is evaluated by name against the enumeration alone, so against a
// criterion that narrows by Range it matches exactly the enumerated names and
// nothing else.
//
// For a version=NA query, attr-match compares every attribute but the
// version: a concrete or ranged criterion / entry version is DISJOINT from NA
// under CPE name matching, but the scan simply has no version to evaluate, so
// it is accepted at VersionUnconfirmed (see Accept).
//
// The CPEMatches loop is consulted both as a fallback after a failed Range
// evaluation (out-of-range exceptions) AND independently when the main CPE
// is disjoint from the query (defensive — covers edition-divergence cases
// in source data).
//
// Range and CPEMatches are NOT mutually exclusive: both can be populated and
// their effective predicate is OR'd. This matches the NVD ranged-cpeMatch
// pattern where semver-evaluable bounds go in Range and out-of-range (or
// non-semver) enumerated CPEs go in CPEMatches.
//
// Notably absent from versioncriterion: Package union (CPE is the only
// kind) and Affected nesting (range is flat — Fixed lives directly on the
// criterion rather than wrapped in an Affected struct).
type Criterion struct {
	Vulnerable bool                      `json:"vulnerable,omitempty"`
	FixStatus  *fixstatusTypes.FixStatus `json:"fix_status,omitempty"`
	CPE        CPE                       `json:"cpe,omitempty"`
	Range      *rangeTypes.Range         `json:"range,omitempty"`
	CPEMatches []CPE                     `json:"cpe_matches,omitempty"`
	Fixed      []string                  `json:"fixed,omitempty"`
}

func (c *Criterion) Sort() {
	slices.Sort(c.CPEMatches)
	slices.Sort(c.Fixed)
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		func() int {
			switch {
			case !x.Vulnerable && y.Vulnerable:
				return -1
			case x.Vulnerable && !y.Vulnerable:
				return +1
			default:
				return 0
			}
		}(),
		func() int {
			switch {
			case x.FixStatus == nil && y.FixStatus == nil:
				return 0
			case x.FixStatus == nil && y.FixStatus != nil:
				return -1
			case x.FixStatus != nil && y.FixStatus == nil:
				return +1
			default:
				return fixstatusTypes.Compare(*x.FixStatus, *y.FixStatus)
			}
		}(),
		cmp.Compare(x.CPE, y.CPE),
		func() int {
			switch {
			case x.Range == nil && y.Range == nil:
				return 0
			case x.Range == nil && y.Range != nil:
				return -1
			case x.Range != nil && y.Range == nil:
				return +1
			default:
				return rangeTypes.Compare(*x.Range, *y.Range)
			}
		}(),
		slices.Compare(x.CPEMatches, y.CPEMatches),
		slices.Compare(x.Fixed, y.Fixed),
	)
}

type Query struct {
	CPE string
}

// overlaps reports whether the query and criterion WFNs are non-disjoint —
// their attribute sets intersect, so the CPEs can refer to the same thing. It
// is the basic "these two CPEs match on attributes" test used throughout
// Accept. Requires go-cpe at or after knqyf263/go-cpe#9, which fixed the
// comparison reporting a false overlap for concrete values where one trailing
// numeric segment is a numeric prefix of the other ("5.15.10" vs "5.15.103").
//
// go-cpe evaluates unquoted wildcards on the source side only (NISTIR 7696
// Table 6-2): an attribute whose TARGET value carries one compares as
// UNDEFINED, which IsDisjoint would let through as an overlap. The query is
// passed as the source, so a pattern on the criterion side (target_sw
// "windows*") hits that case; such attributes are re-compared with the roles
// swapped so the pattern is evaluated against the concrete query value. When
// both sides are patterns the relation is undefined either way, and an
// undefined relation never establishes a match. (A pattern in the criterion
// VERSION never reaches this function: Accept neutralises it first.)
func overlaps(q, c common.WellFormedName) bool {
	fwd := matching.CompareWFNs(q, c)
	var rev map[string]matching.Relation
	for attr, rel := range fwd {
		if rel == matching.UNDEFINED {
			if rev == nil {
				rev = matching.CompareWFNs(c, q)
			}
			rel = rev[attr]
		}
		if rel == matching.DISJOINT || rel == matching.UNDEFINED {
			return false
		}
	}
	return true
}

// MatchQuality describes how strongly a Criterion matched a Query. It is a
// source-agnostic property of the CPE relationship alone; how each quality is
// projected onto a consumer's confidence model (e.g. vuls0's exact vs
// vendor:product tiers, or JVN's version-less semantics) is the consumer's
// concern, not this matcher's.
type MatchQuality int

const (
	// MatchQualityUnknown is the zero value: a quality that was never set.
	// Accept only ever returns it together with a non-nil error; on the
	// err == nil path it never appears. So an Unknown with no error signals an
	// uninitialised value or an enum case this code does not handle, which
	// callers treat as a bug.
	MatchQualityUnknown MatchQuality = iota
	// MatchQualityNone means the criterion was evaluated and does NOT accept
	// the query (disjoint attributes, out of range, enumeration miss).
	MatchQualityNone
	// MatchQualityExact means the criterion accepts the query with sufficient
	// version evidence: a concrete query version confirmed by equality, range,
	// or enumeration; a pattern query version ("12.*") that covers the
	// criterion version or an enumerated name; a version=* criterion with no
	// range/cpematches (every version of the product is affected); a
	// version=NA query matched by an NA criterion, an un-narrowed * criterion,
	// or an NA / * cpematches entry (EQUAL / SUPERSET, a match under CPE name
	// matching); OR a query whose version is ANY — the scan asks for all
	// versions of the product, so any match is reported with full confidence
	// (respecting the intent of whoever wrote the query). A set-valued query
	// (ANY or a pattern) is Exact as soon as the criterion intersects it: the
	// query's author chose the set.
	MatchQualityExact
	// MatchQualityVersionUnconfirmed means the criterion accepts the query on
	// every non-version attribute but the version cannot be evaluated because
	// one side carries no comparable version: the criterion version is NA or a
	// pattern (the CPE spec leaves a target-side pattern undefined) against a
	// concrete or pattern query, or the query version is NA against a concrete
	// version, a pattern, a range, or an enumeration with no NA / * entry. All
	// are DISJOINT or undefined under CPE name matching and accepted only as a
	// relaxation. (An NA query against an NA / * criterion or entry is Exact
	// instead — see MatchQualityExact.)
	MatchQualityVersionUnconfirmed
)

func (q MatchQuality) String() string {
	switch q {
	case MatchQualityNone:
		return "None"
	case MatchQualityExact:
		return "Exact"
	case MatchQualityVersionUnconfirmed:
		return "VersionUnconfirmed"
	default:
		return "Unknown"
	}
}

// Accept reports how strongly the criterion matches the query as a
// MatchQuality (None vs Exact vs VersionUnconfirmed) — the CPE analogue of the
// other criterion kinds' Accept (e.g. kbcriterion returns two bools); a richer
// return under the same vocabulary. The branch structure mirrors the
// affected-set semantics documented on Criterion: attribute match, then the
// NA / pattern short-circuit, then narrowing (range / cpematches), with the
// CPEMatches enumeration tried both as an out-of-range fallback and
// (defensively) when the main CPE is disjoint.
//
// # Name matching (CPE Name Matching, NISTIR 7696)
//
// Every attribute is compared with the query as the source and the criterion
// (or a CPEMatches entry) as the target, per Table 6-2 of the spec. String
// comparison is case-insensitive (§6.2). An unquoted "*" matches zero or more
// characters and an unquoted "?" zero or one (§6.3), and either may appear only
// at the beginning and/or end of a value (§5.2).
//
//	source \ target │ ANY │ NA │ i (concrete) │ m (pattern)
//	────────────────┼─────┼────┼──────────────┼────────────
//	ANY             │  =  │ ⊃  │      ⊃       │ undefined
//	NA              │  ⊂  │ =  │      ≠       │ undefined
//	i (concrete)    │  ⊂  │ ≠  │   = or ≠     │ undefined
//	m (pattern)     │  ⊂  │ ≠  │   ⊃ or ≠     │ undefined
//
// Two CPEs overlap when no attribute compares ≠. An undefined cell (pattern on
// the target side) is re-evaluated with the roles swapped, so a criterion-side
// pattern on a non-version attribute is matched against the concrete query
// value like any pattern; patterns on both sides stay undefined, and an
// undefined relation never establishes a match. The version attribute is
// handled by the table below before name matching sees it.
//
// # Version evaluation (Vuls-specific; the CPE spec has no ranges)
//
// Rows are the query version, columns the criterion. "enum" is the CPEMatches
// enumeration (plus, for a pattern query, any packed enumeration a source
// carries). VU is VersionUnconfirmed: the product matched but the version
// could not be evaluated.
//
//	query \ criterion │ NA (-)  │ pattern │ * (no narrowing) │ * + Range                │ * + enum           │ concrete j
//	──────────────────┼─────────┼─────────┼──────────────────┼──────────────────────────┼────────────────────┼──────────────
//	ANY (*)           │ Exact   │ Exact   │ Exact            │ Exact                    │ Exact              │ Exact
//	NA (-)            │ Exact   │ VU      │ Exact            │ VU¹                      │ VU¹                │ VU
//	concrete i        │ VU      │ VU      │ Exact            │ in Range → Exact,        │ entry = i → Exact, │ i = j → Exact,
//	                  │         │         │                  │ else try enum, else None │ else None          │ else None
//	pattern m         │ VU      │ VU      │ Exact            │ entry ⊂ m → Exact,       │ entry ⊂ m → Exact, │ j ⊂ m → Exact,
//	                  │         │         │                  │ else None                │ else None          │ else None
//
//	¹ an NA or * entry in the enumeration lifts it to Exact.
//
// Range is consulted only for a concrete query: a pattern is evaluated by name
// against the enumeration alone, so a criterion that expresses its affected
// versions only as a Range matches no pattern. An NA or pattern criterion
// version fixes the product but not the version, so it ignores narrowing and
// reports VU for every query but ANY. A CPEMatches entry whose own version is
// a pattern behaves like a pattern criterion (VU); the strongest result across
// the entries wins.
func (c Criterion) Accept(query Query) (MatchQuality, error) {
	qWFN, err := naming.UnbindFS(query.CPE)
	if err != nil {
		return MatchQualityUnknown, errors.Wrapf(err, "unbind %q to WFN", query.CPE)
	}

	cWFN, err := naming.UnbindFS(string(c.CPE))
	if err != nil {
		return MatchQualityUnknown, errors.Wrapf(err, "unbind %q to WFN", string(c.CPE))
	}

	cv := cWFN.GetString(common.AttributeVersion)
	qv := qWFN.GetString(common.AttributeVersion)

	switch {
	case qv == "NA":
		// The scan has no version; its own path covers the main CPE and the
		// CPEMatches together.
		return c.acceptNAQuery(qWFN, cWFN)
	case cv == "NA" || common.ContainsWildcards(cv):
		// A version=NA criterion fixes the product but not the version: it
		// matches any scan whose non-version attributes are compatible. A
		// criterion whose version is a pattern ("4.*") is treated the same
		// way: the CPE spec leaves a target-side pattern undefined, and such
		// criteria are rare mistakes in source data rather than a used
		// feature. The criterion version is neutralised to ANY because
		// go-cpe's comparison would otherwise reject the scan version against
		// NA / undefined; other concrete attributes (target_sw, edition, ...)
		// must still agree.
		cAnyVer, err := withAnyVersion(cWFN)
		if err != nil {
			return MatchQualityUnknown, errors.Wrap(err, "neutralise criterion version")
		}
		if overlaps(qWFN, cAnyVer) {
			// query=ANY asks for all versions → Exact. A concrete scan
			// version is DISJOINT from NA under CPE name matching; it is
			// accepted only as a relaxation mirroring go-cve-dictionary's
			// VendorProductMatch for "-" entries, where NA often means "all
			// versions" (e.g. linux_kernel:- on a classic all-versions CVE),
			// so the version stays unconfirmed.
			if qv == "ANY" {
				return MatchQualityExact, nil
			}
			return MatchQualityVersionUnconfirmed, nil
		}
		// Non-version attributes disagree; fall through to CPEMatches.
	case overlaps(qWFN, cWFN):
		switch {
		case qv == "ANY":
			// The scan asks for all versions of this product (version=*), so
			// any accepted criterion is a confident match regardless of how it
			// narrows versions — respecting the query author's intent.
			// (Deliberately stronger than go-cve-dictionary, which reports a
			// version-less query at vendor:product.)
			return MatchQualityExact, nil
		case c.Range == nil && len(c.CPEMatches) == 0:
			// No narrowing → accept on attribute match alone.
			// version=* (every version of the product is affected), a
			// concrete query equal to the concrete criterion version, or a
			// pattern query covering it (a non-overlapping one would have
			// failed the overlaps check above).
			return MatchQualityExact, nil
		case common.ContainsWildcards(qv):
			// A pattern query ("12.*") denotes a set of names, which no Range
			// can evaluate; it is matched by name against the CPEMatches
			// enumeration below and nothing else.
		case c.Range != nil:
			// Concrete query against a range: accept only if in range,
			// otherwise fall through to CPEMatches.
			// WFN attribute values escape every special character with a
			// backslash ("10\.1\.3\-h1"); unescape so versions containing
			// any special char (e.g. the hyphen in PAN-OS hotfixes) reach the
			// comparator intact.
			qVersion := unescapeWFN(qv)
			// A PAN-OS query may carry the hotfix in the UPDATE attribute
			// (NVD/cisco form: version="10.1.14", update="h11") rather than in
			// the version (snmp2cpe form: "10.1.14-h11"). Fold a hotfix-looking
			// UPDATE into the version so the pan-os comparator sees the full
			// release; otherwise the query reads as the base version and
			// over-matches at hotfix fix boundaries (e.g. accepted by "< 10.1.14-h13"
			// when the device is actually fixed). Scoped to the pan-os range type
			// (other range types do not use the UPDATE attribute this way); for
			// the snmp2cpe form UPDATE is ANY and nothing is folded.
			//
			// Normalise to the lowercase "-hN" the comparator requires (it
			// rejects "-H11"), and only fold when the version is a base release —
			// if it already carries a hotfix ("10.1.14-h11"), appending the
			// UPDATE would produce an unparseable "...-h11-h11".
			if c.Range.Type == rangeTypes.RangeTypePANOS && !strings.Contains(qVersion, "-") {
				if u := unescapeWFN(qWFN.GetString(common.AttributeUpdate)); panosHotfixUpdate.MatchString(u) {
					qVersion = fmt.Sprintf("%s-%s", qVersion, strings.ToLower(u))
				}
			}
			// OpenSSH splits the same way, and NVD is the side that splits it:
			// 9.9p1 is published as version="9.9", update="p1". Unfolded, every
			// portable release of one base reads as that base, so an advisory
			// bounded at "<= 9.9p1" would accept the 9.9p2 that fixes it.
			// Scoped to the openssh range type; a query already carrying the
			// suffix in the version has UPDATE as ANY and nothing is folded.
			if c.Range.Type == rangeTypes.RangeTypeOpenSSH && !opensshPortableVersion.MatchString(qVersion) {
				if u := unescapeWFN(qWFN.GetString(common.AttributeUpdate)); opensshPortableUpdate.MatchString(u) {
					qVersion = fmt.Sprintf("%s%s", qVersion, strings.ToLower(u))
				}
			}
			isAccepted, err := c.Range.Accept(qVersion)
			if err != nil {
				return MatchQualityUnknown, errors.Wrap(err, "range accept")
			}
			if isAccepted {
				return MatchQualityExact, nil
			}
		default:
			// CPEMatches-only narrowing; fall through to CPEMatches.
		}
	default:
		// Main CPE disjoint from the query; only CPEMatches can still match.
	}

	// CPEMatches: tried when (a) main CPE matched but neither the NA / pattern
	// short-circuit nor Range accepted (out-of-Range exceptions, or a pattern
	// query), or (b) main CPE was disjoint (defensive — covers
	// edition-divergence cases in source data). The query version is ANY,
	// concrete or a pattern here (an NA query takes acceptNAQuery), and any of
	// them is confirmed by an overlapping entry. An entry whose own version is
	// a pattern is treated like a pattern criterion: VU for every query but
	// ANY. The strongest entry wins, so the result does not depend on entry
	// order.
	quality := MatchQualityNone
	for _, m := range c.CPEMatches {
		mWFN, err := naming.UnbindFS(string(m))
		if err != nil {
			return MatchQualityUnknown, errors.Wrapf(err, "unbind %q to WFN", string(m))
		}
		if common.ContainsWildcards(mWFN.GetString(common.AttributeVersion)) {
			mAnyVer, err := withAnyVersion(mWFN)
			if err != nil {
				return MatchQualityUnknown, errors.Wrap(err, "neutralise cpe match version")
			}
			if overlaps(qWFN, mAnyVer) {
				if qv == "ANY" {
					return MatchQualityExact, nil
				}
				quality = MatchQualityVersionUnconfirmed
			}
			continue
		}
		if overlaps(qWFN, mWFN) {
			return MatchQualityExact, nil
		}
	}

	return quality, nil
}

// acceptNAQuery is Accept for a version=NA query: the scan has no version.
// Only an NA (EQUAL) or * (SUPERSET) version matches it under CPE name
// matching, and that is Exact. A concrete version, a range, or an enumeration
// of concrete versions is DISJOINT from NA, yet the scan simply has no version
// to evaluate against it — the mirror of an NA criterion against a concrete
// scan — so it is accepted at VersionUnconfirmed when every non-version
// attribute agrees. Anything else is None.
func (c Criterion) acceptNAQuery(qWFN, cWFN common.WellFormedName) (MatchQuality, error) {
	qAnyVer, err := withAnyVersion(qWFN)
	if err != nil {
		return MatchQualityUnknown, errors.Wrap(err, "neutralise query version")
	}

	quality := MatchQualityNone
	switch {
	case overlaps(qWFN, cWFN):
		// Only an NA (EQUAL) or * (SUPERSET) criterion version overlaps an NA
		// query; a concrete version is DISJOINT and a pattern, evaluated with
		// the roles swapped, is DISJOINT too (Table 6-2, row 16). NA fixes
		// the product but not the version and ignores narrowing (as for any
		// query); * without narrowing affects every version.
		if cWFN.GetString(common.AttributeVersion) == "NA" || (c.Range == nil && len(c.CPEMatches) == 0) {
			return MatchQualityExact, nil
		}
		// A * criterion narrowed by a range / enumeration: the range cannot
		// be evaluated against no version, but an NA or * entry below can
		// still match.
		quality = MatchQualityVersionUnconfirmed
	case overlaps(qAnyVer, cWFN):
		// A concrete (or wildcard-pattern) criterion version against no
		// version.
		quality = MatchQualityVersionUnconfirmed
	default:
		// Non-version attributes disagree; only CPEMatches can still match.
	}

	// The strongest entry wins, so the result does not depend on entry order
	// (Sort puts "*" before "-", and before concrete versions).
	for _, m := range c.CPEMatches {
		mWFN, err := naming.UnbindFS(string(m))
		if err != nil {
			return MatchQualityUnknown, errors.Wrapf(err, "unbind %q to WFN", string(m))
		}
		switch {
		case overlaps(qWFN, mWFN):
			// An NA or * entry (see the main CPE case above).
			return MatchQualityExact, nil
		case overlaps(qAnyVer, mWFN):
			// A concrete (or wildcard-pattern) entry against no version.
			quality = MatchQualityVersionUnconfirmed
		default:
		}
	}

	return quality, nil
}

// withAnyVersion returns a copy of wfn whose version is ANY, for comparing
// every attribute but the version.
func withAnyVersion(wfn common.WellFormedName) (common.WellFormedName, error) {
	anyVal, err := common.NewLogicalValue("ANY")
	if err != nil {
		return nil, errors.Wrap(err, "build ANY logical value")
	}
	out := maps.Clone(wfn)
	if err := out.Set(common.AttributeVersion, anyVal); err != nil {
		return nil, errors.Wrap(err, "set version")
	}
	return out, nil
}

// panosHotfixUpdate matches a PAN-OS hotfix encoded in the WFN UPDATE
// attribute ("h11"), the form NVD/cisco-style CPEs use. The snmp2cpe scanner
// instead carries the hotfix in the version attribute ("10.1.14-h11"); both
// must reach the pan-os comparator as the full "X.Y.Z-hN" release.
var panosHotfixUpdate = regexp.MustCompile(`^[hH][0-9]+$`)

// opensshPortableUpdate matches an OpenSSH portable release encoded in the WFN
// UPDATE attribute ("p1"), which is how NVD publishes it, and
// opensshPortableVersion recognises the form that already carries it in the
// version ("9.9p1"). Either must reach the openssh comparator as the full
// release.
var (
	opensshPortableUpdate  = regexp.MustCompile(`^[pP][0-9]+$`)
	opensshPortableVersion = regexp.MustCompile(`[pP][0-9]+$`)
)

// unescapeWFN reverses WFN attribute escaping: a backslash escapes the
// character that follows it (e.g. "10\.1\.3\-h1" -> "10.1.3-h1"). The escape
// marker is consumed while the escaped character is preserved, so an escaped
// backslash ("\\") yields a single literal backslash. A trailing lone
// backslash is kept as-is.
func unescapeWFN(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
