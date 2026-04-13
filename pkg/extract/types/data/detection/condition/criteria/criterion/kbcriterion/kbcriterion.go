package kbcriterion

import (
	"cmp"
	"slices"

	"github.com/pkg/errors"
)

type Criterion struct {
	Product string `json:"product,omitempty"`
	KBID    string `json:"kb_id,omitempty"`
}

func (c *Criterion) Sort() {}

func Compare(x, y Criterion) int {
	return cmp.Or(
		cmp.Compare(x.Product, y.Product),
		cmp.Compare(x.KBID, y.KBID),
	)
}

type Query struct {
	// AcceptProducts restricts KB criterion matching to only those criteria
	// whose Product is in this set. This prevents a KB criterion for an
	// unrelated product (e.g., ARM64 variant) from being accepted when
	// the host runs a different product (e.g., x64 variant).
	// Callers must provide at least one product; Accept returns an error
	// when this slice is empty.
	AcceptProducts []string

	// CoveredKBs is the set of KBs covered by an applied superseding KB.
	// When non-empty, the KB criterion uses covered-based evaluation:
	// a KB is considered vulnerable when it is NOT in CoveredKBs. This
	// treats undiscovered KBs (not found by chain walking) as "not covered"
	// (conservatively vulnerable) rather than "not unapplied."
	CoveredKBs []string

	// UnappliedKBs is the set of KBs discovered by supersession chain
	// walking that are not covered by any applied KB. Used as a fallback
	// when CoveredKBs is empty: a KB is considered vulnerable when it IS
	// in UnappliedKBs.
	UnappliedKBs []string
}

func (c Criterion) Accept(query Query) (byCovered, byUnapplied bool, err error) {
	if len(query.AcceptProducts) == 0 {
		return false, false, errors.New("AcceptProducts must not be empty")
	}
	if !slices.Contains(query.AcceptProducts, c.Product) {
		return false, false, nil
	}
	if len(query.CoveredKBs) > 0 {
		return !slices.Contains(query.CoveredKBs, c.KBID), false, nil
	}
	return false, slices.Contains(query.UnappliedKBs, c.KBID), nil
}
