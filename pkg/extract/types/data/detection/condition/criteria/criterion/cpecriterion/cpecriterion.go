package cpecriterion

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
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
// The affected set is described by the main CPE and an enumeration, which
// Accept evaluates independently of each other and combines by taking the
// stronger result:
//   - CPE: the criterion's canonical CPE string (wildcards permitted). A
//     version of * is every version of the product unless a Range or an
//     enumeration narrows it.
//   - Range: optional version range, the version of a * criterion
//     (comparator selected by Range.Type — semver / loose version / etc.).
//     It is evaluated for a concrete query version only. A criterion whose
//     version is not * leaves nothing for a range to decide, so the Range
//     is ignored there (no source emits that shape).
//   - CPEMatches: optional list of concrete CPE strings that the criterion
//     also covers — used for entries that fall OUTSIDE Range (e.g. NVD listed
//     versions that don't satisfy the bounds) or that Range cannot evaluate
//     at all (RangeTypeUnknown / non-parseable versions). Each entry is a
//     whole name matched on its own; the main CPE is not consulted for it.
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
//	strongest of (
//	    main CPE: attr-match AND (
//	        query version is ANY                        // the scan asks for every version
//	        OR version=* narrowed by Range / CPEMatches // concrete query: Range; pattern query: nothing; NA query: VU
//	        OR versions intersect                       // NA = NA, un-narrowed *, concrete / pattern
//	        OR one version is NA                        // VU: no version to evaluate
//	    ),
//	    each CPEMatches[i]: attr-match AND (versions intersect OR one version is NA → VU)
//	)
//
// Range is consulted only for a concrete query version. A pattern query
// ("12.*") is evaluated by name against the enumeration alone, so against a
// criterion that narrows by Range it matches exactly the enumerated names and
// nothing else; Accept records a warning when that leaves the result below
// Exact.
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

// overlapsExceptVersion reports whether the query and criterion (or
// CPEMatches entry) WFNs match under CPE name matching on every attribute but
// the version, the first of the two tables on Accept: each attribute's sets
// intersect, so the CPEs can refer to the same product. Each attribute is
// related by relateValues, which implements Table 6-2 and resolves its
// undefined cells (a pattern on either side) as the relation of the sets the
// patterns denote; go-cpe's matching package is not used, as it evaluates
// wild cards on the source side only and reports a target-side pattern as
// UNDEFINED. The version is related by the caller, which also owns the
// Vuls-specific rules for it (Range, NA).
func overlapsExceptVersion(q, c common.WellFormedName) bool {
	for _, attr := range []string{
		common.AttributePart, common.AttributeVendor, common.AttributeProduct,
		common.AttributeUpdate, common.AttributeEdition, common.AttributeLanguage, common.AttributeSwEdition,
		common.AttributeTargetSw, common.AttributeTargetHw, common.AttributeOther,
	} {
		if relateValues(q.Get(attr), c.Get(attr)) == relationDisjoint {
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
	// version evidence: the query version (a concrete value, a pattern such
	// as "12.*", or ANY) intersects the criterion version, an enumerated name,
	// or — for a concrete query — the Range; a version=NA query matched by an
	// NA criterion, an un-narrowed * criterion, or an NA / * cpematches entry
	// (EQUAL / SUPERSET, a match under CPE name matching). A set-valued query
	// (a pattern or ANY) is Exact as soon as the criterion intersects it: the
	// query's author chose the set, and any affected version inside it is
	// reported with full confidence. (For ANY this is deliberately stronger
	// than go-cve-dictionary, which reported a version-less query at
	// vendor:product.)
	MatchQualityExact
	// MatchQualityVersionUnconfirmed means the criterion accepts the query on
	// every non-version attribute but the version cannot be confirmed because
	// one side has none: the criterion (or entry) version is NA against a
	// concrete or pattern query, or the query version is NA against a
	// concrete version, a pattern, a range, or an enumeration with no NA / *
	// entry. Both are DISJOINT under CPE name matching and accepted only as a
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

// stronger returns the stronger of two qualities, ordered None <
// VersionUnconfirmed < Exact (not the declaration order, which is fixed by
// the zero value being Unknown). Unknown never reaches it.
func stronger(a, b MatchQuality) MatchQuality {
	rank := func(q MatchQuality) int {
		switch q {
		case MatchQualityNone:
			return 1
		case MatchQualityVersionUnconfirmed:
			return 2
		case MatchQualityExact:
			return 3
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Accept reports how strongly the criterion matches the query as a
// MatchQuality (None vs Exact vs VersionUnconfirmed) — the CPE analogue of the
// other criterion kinds' Accept (e.g. kbcriterion returns two bools); a richer
// return under the same vocabulary. The main CPE and each CPEMatches entry
// are evaluated separately (acceptMain, acceptEntry) and the strongest result
// wins, so the result depends neither on entry order nor on the main CPE
// matching before an entry is tried (edition divergence in source data).
//
// The warnings are the non-fatal events the evaluation itself records — as
// opposed to the *warning.UnevaluableError the error channel carries when
// the data cannot be evaluated at all. Today there is one: a pattern query
// against a criterion that narrows by Range, when the enumeration did not
// make the result Exact (warning.KindPatternQueryRange, Cause = the query
// CPE). It is nil when there is none.
//
// # Name matching (CPE Name Matching, NISTIR 7696)
//
// Every attribute is compared with the query as the source and the criterion
// (or a CPEMatches entry) as the target, per Table 6-2 of the spec. String
// comparison is case-insensitive (§6.2). An unquoted "*" matches zero or more
// characters and an unquoted "?" zero or one (§6.3), and either may appear only
// at the beginning and/or end of a value (NISTIR 7695 §5.3.2).
//
//	source \ target │ ANY │ NA │ i (concrete) │ m (pattern)
//	────────────────┼─────┼────┼──────────────┼────────────
//	ANY             │  =  │ ⊃  │      ⊃       │ undefined
//	NA              │  ⊂  │ =  │      ≠       │ undefined
//	i (concrete)    │  ⊂  │ ≠  │   = or ≠     │ undefined
//	m (pattern)     │  ⊂  │ ≠  │   ⊃ or ≠     │ undefined
//
// Two CPEs overlap when no attribute compares ≠. relateValues implements the
// table and resolves its undefined cells: the spec's grammar (wild cards only
// at the ends of a value) makes every value a set of strings — a concrete
// value a singleton, ANY every string, a pattern the strings it denotes — so
// a pattern on either side, or on both, is related as a set: =, ⊂, ⊃, a
// partial overlap, or ≠. Any intersection is a match on that attribute; the
// direction of containment does not matter. This holds for the version too,
// subject to the Vuls-specific rules below.
//
// # Version evaluation (Vuls-specific; the CPE spec has no ranges)
//
// Rows are the query version, columns the criterion version. Both tables
// assume every other attribute intersects; otherwise the cell is None.
// "narrowed" is a * criterion that carries a Range and/or a CPEMatches
// enumeration. VU is VersionUnconfirmed: the product matched but there is no
// version to evaluate.
//
// The main CPE:
//
//	query \ criterion │ NA (-) │ pattern m          │ concrete j       │ * not narrowed │ * + Range           │ * + enumeration only
//	──────────────────┼────────┼────────────────────┼──────────────────┼────────────────┼─────────────────────┼─────────────────────
//	ANY (*)           │ Exact  │ Exact              │ Exact            │ Exact          │ Exact               │ Exact
//	NA (-)            │ Exact  │ VU                 │ VU               │ Exact          │ VU                  │ VU
//	concrete i        │ VU     │ i ∈ m → Exact,     │ i = j → Exact,   │ Exact          │ in Range → Exact,   │ None
//	                  │        │ else None          │ else None        │                │ else None           │
//	pattern p         │ VU     │ p ∩ m ≠ ∅ → Exact, │ j ∈ p → Exact,   │ Exact          │ None, with a        │ None
//	                  │        │ else None          │ else None        │                │ warning (see below) │
//
// Each CPEMatches entry, on its own name:
//
//	query \ entry │ NA (-) │ pattern m          │ concrete j       │ *
//	──────────────┼────────┼────────────────────┼──────────────────┼──────
//	ANY (*)       │ Exact  │ Exact              │ Exact            │ Exact
//	NA (-)        │ Exact  │ VU                 │ VU               │ Exact
//	concrete i    │ VU     │ i ∈ m → Exact,     │ i = j → Exact,   │ Exact
//	              │        │ else None          │ else None        │
//	pattern p     │ VU     │ p ∩ m ≠ ∅ → Exact, │ j ∈ p → Exact,   │ Exact
//	              │        │ else None          │ else None        │
//
// The criterion's result is the strongest cell over the main CPE and every
// entry. A * + Range + enumeration criterion is read off both tables: with
// Range < 2.0 and an NA entry, 1.0 is Exact (the Range), 2.0 is VU (the
// entry), a pattern query is VU (the entry) and an NA query is Exact (the
// entry). A Range on a criterion whose version is not * is ignored; the
// concrete j column applies.
//
// Three rules produce the tables:
//
//  1. Name matching: every attribute's sets must intersect (the first table
//     on Accept). For the version this means a concrete, pattern or ANY
//     query is Exact against any criterion or entry version it intersects,
//     including a pattern it only partly overlaps: the query's author chose
//     the set, and any affected version inside it is reported.
//  2. NA: a version of NA on either side, against a concrete version, a
//     pattern, or a narrowed *, is VU rather than None — the product matched
//     but one side has no version to evaluate. NA against NA or an
//     un-narrowed * is Exact by rule 1.
//  3. Narrowing: a * criterion with a Range and/or an enumeration is not
//     accepted by its version alone. A concrete query is accepted by the
//     Range; a pattern query by nothing, since no Range can evaluate a set
//     of names, and the warning records that the Range was skipped unless
//     an entry made the result Exact anyway; an ANY query ignores narrowing;
//     an NA query is VU by rule 2. The entries are tried in every case.
func (c Criterion) Accept(query Query) (MatchQuality, []warningTypes.Warning, error) {
	qWFN, err := naming.UnbindFS(query.CPE)
	if err != nil {
		return MatchQualityUnknown, nil, errors.Wrapf(err, "unbind %q to WFN", query.CPE)
	}

	cWFN, err := naming.UnbindFS(string(c.CPE))
	if err != nil {
		return MatchQualityUnknown, nil, errors.Wrapf(err, "unbind %q to WFN", string(c.CPE))
	}

	// Exact is the strongest quality: once the main CPE or an entry reaches
	// it there is nothing left to evaluate, and nothing to warn about.
	quality, rangeSkipped, err := c.acceptMain(qWFN, cWFN)
	if err != nil {
		return MatchQualityUnknown, nil, errors.Wrap(err, "accept main cpe")
	}
	if quality == MatchQualityExact {
		return quality, nil, nil
	}

	for _, m := range c.CPEMatches {
		mWFN, err := naming.UnbindFS(string(m))
		if err != nil {
			return MatchQualityUnknown, nil, errors.Wrapf(err, "unbind %q to WFN", string(m))
		}
		if quality = stronger(quality, acceptEntry(qWFN, mWFN)); quality == MatchQualityExact {
			return quality, nil, nil
		}
	}

	// None or VersionUnconfirmed: a Range skipped for a pattern query is
	// what could have made the difference.
	var ws []warningTypes.Warning
	if rangeSkipped {
		ws = append(ws, warningTypes.Warning{Kind: warningTypes.KindPatternQueryRange, Cause: query.CPE})
	}
	return quality, ws, nil
}

// acceptMain evaluates the query against the main CPE: the first table on
// Accept. rangeSkipped reports that the criterion narrows by a Range which
// was not consulted because the query version is a pattern.
func (c Criterion) acceptMain(qWFN, cWFN common.WellFormedName) (quality MatchQuality, rangeSkipped bool, err error) {
	if !overlapsExceptVersion(qWFN, cWFN) {
		return MatchQualityNone, false, nil
	}

	// The logical values are told apart by type (isNA / isANY): GetString
	// renders them as "NA" / "ANY", which a concrete version may spell too.
	qVer, cVer := qWFN.Get(common.AttributeVersion), cWFN.Get(common.AttributeVersion)
	switch {
	case isANY(qVer):
		// The scan asks for all versions of this product (version=*), so
		// any criterion whose other attributes agree is a confident match
		// regardless of how it narrows versions — respecting the query
		// author's intent. (Deliberately stronger than go-cve-dictionary,
		// which reports a version-less query at vendor:product.)
		return MatchQualityExact, false, nil
	case isANY(cVer) && (c.Range != nil || len(c.CPEMatches) > 0):
		// A narrowed *: the version alone decides nothing (rule 3).
		switch {
		case isNA(qVer):
			// The scan has no version to evaluate against the narrowing
			// (rule 2); an NA / * entry can still make it Exact.
			return MatchQualityVersionUnconfirmed, false, nil
		case c.Range == nil:
			// Enumeration only: the entries decide.
			return MatchQualityNone, false, nil
		case hasWildcards(qWFN.GetString(common.AttributeVersion)):
			// A pattern query ("12.*") denotes a set of names, which no
			// Range can evaluate; the entries decide, and the skipped Range
			// is reported unless they make the result Exact.
			return MatchQualityNone, true, nil
		default:
			isAccepted, err := c.acceptRange(qWFN)
			if err != nil {
				return MatchQualityUnknown, false, errors.Wrap(err, "range accept")
			}
			if isAccepted {
				return MatchQualityExact, false, nil
			}
			return MatchQualityNone, false, nil
		}
	case relateValues(qVer, cVer) != relationDisjoint:
		// Name matching decides (rule 1): NA against NA or an un-narrowed *,
		// a concrete / pattern criterion version the query intersects, an
		// un-narrowed * against anything. A Range on a non-* criterion is
		// not consulted — the version already is the affected set.
		return MatchQualityExact, false, nil
	case isNA(qVer) || isNA(cVer):
		// One side has no version (rule 2): a version=NA criterion fixes
		// the product but not the version (e.g. linux_kernel:- on a classic
		// all-versions CVE, where go-cve-dictionary reported
		// VendorProductMatch), or the scan reports none. Accepted as a
		// relaxation of name matching, the version left unconfirmed.
		return MatchQualityVersionUnconfirmed, false, nil
	default:
		return MatchQualityNone, false, nil
	}
}

// acceptEntry evaluates the query against one CPEMatches entry on the
// entry's own name: the second table on Accept. An entry whose version is NA
// is treated like an NA criterion (rule 2).
func acceptEntry(qWFN, mWFN common.WellFormedName) MatchQuality {
	if !overlapsExceptVersion(qWFN, mWFN) {
		return MatchQualityNone
	}
	qVer, mVer := qWFN.Get(common.AttributeVersion), mWFN.Get(common.AttributeVersion)
	switch {
	case relateValues(qVer, mVer) != relationDisjoint:
		return MatchQualityExact
	case isNA(qVer) || isNA(mVer):
		return MatchQualityVersionUnconfirmed
	default:
		return MatchQualityNone
	}
}

// acceptRange evaluates a concrete query version against the criterion's
// Range, folding a release suffix the query may carry in its UPDATE
// attribute into the version where the comparator expects it there.
func (c Criterion) acceptRange(qWFN common.WellFormedName) (bool, error) {
	// WFN attribute values escape every special character with a backslash
	// ("10\.1\.3\-h1"); unescape so versions containing any special char
	// (e.g. the hyphen in PAN-OS hotfixes) reach the comparator intact.
	qVersion := unescapeWFN(qWFN.GetString(common.AttributeVersion))
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
	return c.Range.Accept(qVersion)
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
