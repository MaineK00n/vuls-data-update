package cpecriterionrange

import (
	"cmp"

	"github.com/hashicorp/go-version"
)

// Range is a semver-only version constraint for a CPE criterion. There is no
// Type field (CPE-side matching only meaningfully composes with semver), no
// Fixed list, and the criterion holds a single Range (not a slice).
type Range struct {
	GreaterEqual string `json:"ge,omitempty"`
	GreaterThan  string `json:"gt,omitempty"`
	LessEqual    string `json:"le,omitempty"`
	LessThan     string `json:"lt,omitempty"`
}

func Compare(x, y Range) int {
	return cmp.Or(
		cmp.Compare(x.GreaterEqual, y.GreaterEqual),
		cmp.Compare(x.GreaterThan, y.GreaterThan),
		cmp.Compare(x.LessEqual, y.LessEqual),
		cmp.Compare(x.LessThan, y.LessThan),
	)
}

// Accept returns true when v satisfies every non-empty bound on r, parsing
// both r's bounds and v as semver. An unparseable version (bound or query) is
// treated as "out of range" without an error so that callers can still try
// alternative detection paths (e.g. CPEMatches enumeration).
func (r Range) Accept(v string) (bool, error) {
	qv, err := version.NewSemver(v)
	if err != nil {
		return false, nil
	}

	if r.GreaterEqual != "" {
		bv, err := version.NewSemver(r.GreaterEqual)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) < 0 {
			return false, nil
		}
	}
	if r.GreaterThan != "" {
		bv, err := version.NewSemver(r.GreaterThan)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) <= 0 {
			return false, nil
		}
	}
	if r.LessEqual != "" {
		bv, err := version.NewSemver(r.LessEqual)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) > 0 {
			return false, nil
		}
	}
	if r.LessThan != "" {
		bv, err := version.NewSemver(r.LessThan)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) >= 0 {
			return false, nil
		}
	}
	return true, nil
}
