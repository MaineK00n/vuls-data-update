package cpecriterion

import (
	"cmp"
	"slices"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

type CPE string

// Criterion represents a CPE-only detection criterion.
//   - CPE: the criterion's canonical CPE string (wildcards permitted)
//   - Range: optional version range narrowing the match (comparator selected
//     by Range.Type — semver / loose version / etc.)
//   - CPEMatches: optional list of concrete CPE strings that the criterion
//     also covers — used for entries that fall OUTSIDE Range (e.g. NVD listed
//     versions that don't satisfy the bounds) or that Range cannot evaluate
//     at all (RangeTypeUnknown / non-parseable versions)
//   - Vulnerable: a tag for downstream consumers (e.g. to distinguish the
//     vulnerable side from a hardware guard under AND); NOT consulted by
//     Accept (consistent with versioncriterion.Criterion.Accept)
//
// Detection semantics (see Accept):
//
//	CPE-attr-match AND (
//	    c.version=="NA"                       // NA short-circuit (ignores narrowing)
//	    OR (Range==nil AND CPEMatches==nil)   // no narrowing
//	    OR query-version is ANY/NA            // no concrete version to compare
//	    OR Range matches
//	    OR any CPEMatches[i] attr-match
//	)
//
// Range and CPEMatches are NOT mutually exclusive: both can be populated and
// their effective predicate is OR'd. This matches the NVD ranged-cpeMatch
// pattern where semver-evaluable bounds go in Range and out-of-range (or
// non-semver) enumerated CPEs go in CPEMatches.
//
// Notably absent from versioncriterion: FixStatus (no fix-state semantics on
// CPE), Package union (CPE is the only kind), Affected nesting (range is flat).
type Criterion struct {
	Vulnerable bool              `json:"vulnerable,omitempty"`
	CPE        CPE               `json:"cpe,omitempty"`
	Range      *rangeTypes.Range `json:"range,omitempty"`
	CPEMatches []string          `json:"cpe_matches,omitempty"`
}

func (c *Criterion) Sort() {
	slices.Sort(c.CPEMatches)
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
	)
}

type Query struct {
	CPE string
}

func (c Criterion) Accept(query Query) (bool, error) {
	qWFN, err := naming.UnbindFS(query.CPE)
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", query.CPE)
	}

	cWFN, err := naming.UnbindFS(string(c.CPE))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(c.CPE))
	}

	if !matching.IsDisjoint(qWFN, cWFN) {
		// c.version="NA" short-circuits: NA makes any subsequent version
		// narrowing semantically meaningless.
		if cWFN.GetString(common.AttributeVersion) == "NA" {
			return true, nil
		}
		// No narrowing → accept on attribute match alone.
		if c.Range == nil && len(c.CPEMatches) == 0 {
			return true, nil
		}
		// ANY / NA on the query side has no concrete version to compare;
		// match (consistent with legacy versioncriterion CPE handling).
		switch qWFN.GetString(common.AttributeVersion) {
		case "ANY", "NA":
			return true, nil
		}
		if c.Range != nil {
			qVersion := strings.ReplaceAll(qWFN.GetString(common.AttributeVersion), "\\.", ".")
			isAccepted, err := c.Range.Accept(qVersion)
			if err != nil {
				return false, errors.Wrap(err, "range accept")
			}
			if isAccepted {
				return true, nil
			}
		}
		// Fall through to CPEMatches: out-of-range (or non-semver) exceptions
		// the Range alone could not capture.
	}

	// CPEMatches: tried when (a) main CPE matched but neither NA short-circuit
	// nor Range accepted (out-of-Range exceptions), or (b) main CPE was
	// disjoint (defensive — covers edition-divergence cases in source data).
	for _, m := range c.CPEMatches {
		mWFN, err := naming.UnbindFS(m)
		if err != nil {
			return false, errors.Wrapf(err, "unbind %q to WFN", m)
		}
		if !matching.IsDisjoint(qWFN, mWFN) {
			return true, nil
		}
	}

	return false, nil
}
