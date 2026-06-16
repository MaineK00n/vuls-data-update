package cpecriterion

import (
	"cmp"
	"maps"
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
// Detection semantics (see Accept):
//
//	(CPE-attr-match AND (
//	    c.version=="NA"                          // NA short-circuit (ignores narrowing)
//	    OR (Range==nil AND len(CPEMatches)==0)   // no narrowing
//	    OR query-version is ANY/NA               // no concrete version to compare
//	    OR Range matches
//	))
//	OR any CPEMatches[i] attr-match              // also tried when main CPE is disjoint
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

// concretelyDisjoint reports whether two WFNs disagree byte-wise on any
// concrete (non-ANY/NA) attribute. It exists to work around an upstream
// go-cpe matching bug: matching.IsDisjoint returns false (and
// matching.IsSuperset returns true) for two concrete values where the
// trailing numeric segment of one is a numeric prefix of the other —
// e.g. version "5.15.10" is reported as a "superset" of "5.15.103",
// or "5.15" of "5.150". Alphabetic substrings ("linux_kernel" vs
// "linux_kernel_extra") and dot-boundary segment additions ("5.15" vs
// "5.15.10") are NOT affected. The bug let exact-match criteria fire
// on unrelated concrete versions and produced false positives during
// vuls-compare runs against linux_kernel.
//
// Tracked upstream as knqyf263/go-cpe#3 (issue) with a fix proposed in
// knqyf263/go-cpe#9; this spot-check can be dropped once that fix lands
// and we bump the dependency.
//
// The check runs on every attribute (not just version) for robustness
// against future go-cpe regressions; wildcard / ANY / NA values fall
// through unchanged so legitimate broad-criterion matches still hit.
func concretelyDisjoint(qWFN, cWFN common.WellFormedName) bool {
	for _, a := range []string{
		common.AttributePart,
		common.AttributeVendor,
		common.AttributeProduct,
		common.AttributeVersion,
		common.AttributeUpdate,
		common.AttributeEdition,
		common.AttributeLanguage,
		common.AttributeSwEdition,
		common.AttributeTargetSw,
		common.AttributeTargetHw,
		common.AttributeOther,
	} {
		qv := qWFN.GetString(a)
		cv := cWFN.GetString(a)
		if qv == "ANY" || qv == "NA" || cv == "ANY" || cv == "NA" {
			continue
		}
		if qv != cv {
			return true
		}
	}
	return false
}

// overlaps reports whether two WFNs are non-disjoint — their attribute sets
// intersect, so the CPEs can refer to the same thing. It is matching.IsDisjoint
// negated and corrected with the concretelyDisjoint bug-guard: the basic
// "these two CPEs match on attributes" test used throughout Accept.
func overlaps(a, b common.WellFormedName) bool {
	return !matching.IsDisjoint(a, b) && !concretelyDisjoint(a, b)
}

// MatchQuality describes how strongly a Criterion matched a Query. It is a
// source-agnostic property of the CPE relationship alone; how each quality is
// projected onto a consumer's confidence model (e.g. vuls0's exact vs
// vendor:product tiers, or JVN's version-less semantics) is the consumer's
// concern, not this matcher's.
type MatchQuality int

const (
	// MatchQualityUnknown is the zero value: a quality that was never set.
	// Accept never returns it — its appearance signals an uninitialised value
	// or an enum case this code does not handle, which callers treat as a bug.
	MatchQualityUnknown MatchQuality = iota
	// MatchQualityNone means the criterion was evaluated and does NOT accept
	// the query (disjoint attributes, out of range, enumeration miss).
	MatchQualityNone
	// MatchQualityExact means the criterion accepts the query with sufficient
	// version evidence: a concrete query version confirmed by equality, range,
	// or enumeration, OR a version=* criterion with no range/cpematches (every
	// version of the product is affected).
	MatchQualityExact
	// MatchQualityVersionUnconfirmed means the criterion accepts the query on
	// attribute equality but the query's concrete version cannot be confirmed
	// affected: the criterion version is NA, or the query itself carries no
	// concrete version (ANY/NA) against a version-bearing criterion.
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
// affected-set semantics documented on Criterion: attribute match, then NA
// short-circuit, then narrowing (range / cpematches), with the CPEMatches
// enumeration tried both as an out-of-range fallback and (defensively) when the
// main CPE is disjoint.
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
	// qWFN is fixed for this call, so whether the query carries a concrete
	// version is a single determined value, not a per-branch computation.
	queryVersionless := qv == "ANY" || qv == "NA"

	switch {
	case cv == "NA":
		// A version=NA criterion fixes the product but not the version: it
		// matches any scan whose non-version attributes are compatible, at
		// version-unconfirmed quality. This mirrors go-cve-dictionary's
		// VendorProductMatch for "-" entries, where NA often means "all
		// versions" (e.g. linux_kernel:- on a classic all-versions CVE). The
		// criterion version is neutralised to ANY because go-cpe's IsDisjoint
		// would otherwise reject a concrete scan version against NA; other
		// concrete attributes (target_sw, edition, ...) must still agree.
		cAnyVer := maps.Clone(cWFN)
		anyVal, err := common.NewLogicalValue("ANY")
		if err != nil {
			return MatchQualityUnknown, errors.Wrap(err, "build ANY logical value")
		}
		if err := cAnyVer.Set(common.AttributeVersion, anyVal); err != nil {
			return MatchQualityUnknown, errors.Wrap(err, "neutralise criterion version")
		}
		if overlaps(qWFN, cAnyVer) {
			return MatchQualityVersionUnconfirmed, nil
		}
		// Non-version attributes disagree; fall through to CPEMatches.
	case overlaps(qWFN, cWFN):
		switch {
		case c.Range == nil && len(c.CPEMatches) == 0:
			// No narrowing → accept on attribute match alone.
			switch {
			case cv == "ANY":
				// version=* with no range/cpematches: every version of the
				// product is affected. This "all versions" reading takes
				// precedence over a version-less query.
				return MatchQualityExact, nil
			case queryVersionless:
				return MatchQualityVersionUnconfirmed, nil
			default:
				// Concrete query equal to the concrete criterion version (a
				// differing one would have failed the overlaps check above).
				return MatchQualityExact, nil
			}
		case queryVersionless:
			// Narrowed criterion, but the query has no concrete version to
			// confirm against the range / enumeration.
			return MatchQualityVersionUnconfirmed, nil
		case c.Range != nil:
			// Concrete query against a range: accept only if in range,
			// otherwise fall through to CPEMatches.
			qVersion := strings.ReplaceAll(qv, "\\.", ".")
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

	// CPEMatches: tried when (a) main CPE matched but neither NA short-circuit
	// nor Range accepted (out-of-Range exceptions), or (b) main CPE was
	// disjoint (defensive — covers edition-divergence cases in source data).
	for _, m := range c.CPEMatches {
		mWFN, err := naming.UnbindFS(string(m))
		if err != nil {
			return MatchQualityUnknown, errors.Wrapf(err, "unbind %q to WFN", string(m))
		}
		if overlaps(qWFN, mWFN) {
			// Reached with a version-less query only via the main-CPE-disjoint
			// path (the matched path returns above); it has no version to
			// confirm against the enumerated concrete CPE.
			if queryVersionless {
				return MatchQualityVersionUnconfirmed, nil
			}
			return MatchQualityExact, nil
		}
	}

	return MatchQualityNone, nil
}
