package affected

import (
	"cmp"
	stderrors "errors"
	"slices"

	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Affected struct {
	Type  rangeTypes.RangeType `json:"type,omitempty"`
	Range []rangeTypes.Range   `json:"range,omitempty"`
	Fixed []string             `json:"fixed,omitempty"`
	// Unresolved is set, with Type RangeTypeUnresolved and no Range or Fixed, when
	// the package is known affected but no range can be derived from the vendor's
	// fix: the vendor names it only as a link, a release tag, a version without a
	// comparator, or not at all.
	Unresolved *Unresolved `json:"unresolved,omitempty"`
}

// Unresolved is the vendor's statement of the fix, as published. None of its
// fields is a version that can be compared.
type Unresolved struct {
	// Fixed is the fixed release as the vendor names it, e.g.
	// "https://aka.ms/OfficeSecurityReleases", "11.0 RC1", "17.10.5.1".
	Fixed string `json:"fixed,omitempty"`
	// Description is the vendor's description of the fix, e.g. "Click to Run",
	// "Release Notes".
	Description string `json:"description,omitempty"`
	// URL is the vendor's link for the fix.
	URL string `json:"url,omitempty"`
}

func (a *Affected) Sort() {
	slices.SortFunc(a.Range, rangeTypes.Compare)
	slices.Sort(a.Fixed)
}

func Compare(x, y Affected) int {
	return cmp.Or(
		x.Type.Compare(y.Type),
		slices.CompareFunc(x.Range, y.Range, rangeTypes.Compare),
		slices.Compare(x.Fixed, y.Fixed),
		func() int {
			switch {
			case x.Unresolved == nil && y.Unresolved == nil:
				return 0
			case x.Unresolved == nil && y.Unresolved != nil:
				return -1
			case x.Unresolved != nil && y.Unresolved == nil:
				return +1
			default:
				return cmp.Or(
					cmp.Compare(x.Unresolved.Fixed, y.Unresolved.Fixed),
					cmp.Compare(x.Unresolved.Description, y.Unresolved.Description),
					cmp.Compare(x.Unresolved.URL, y.Unresolved.URL),
				)
			}
		}(),
	)
}

// Accept reports whether version v of the package is affected. An Unresolved
// Affected accepts every version: no range could be derived, so the package is
// affected with its version unconfirmed (the caller records that, see
// IsUnresolved). Type RangeTypeUnresolved and Unresolved come together, and
// Unresolved comes without Range or Fixed; anything else is a producer bug and
// an error.
func (a Affected) Accept(family ecosystemTypes.Ecosystem, v string) (bool, error) {
	ok, err := a.IsUnresolved()
	if err != nil {
		return false, errors.Wrap(err, "is unresolved")
	}
	if ok {
		return true, nil
	}

	for _, r := range a.Range {
		// A Range element with no endpoints expresses nothing — malformed
		// data (no extractor produces one; schema validation is the hard
		// gate) or a newer range type whose constraints live in JSON fields
		// this build's unmarshal drops. Either way the criterion cannot be
		// evaluated: report it as a non-fatal empty-range warning rather
		// than aborting detection in the field. Whether a Type is evaluable
		// is otherwise derived from TestEndpoint (CompareVersions
		// underneath) on the endpoint tests below: anything it has no
		// comparator for (unset, newer-data values, comparator-less
		// vocabulary debt like pacman) answers with
		// *UnsupportedRangeTypeError and is reported as a non-fatal
		// *warning.UnevaluableError.
		if r == (rangeTypes.Range{}) {
			return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}}
		}
		if r.Equal != "" {
			n, err := a.Type.TestEndpoint(family, r.Equal, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.Equal, v)
			}
			if n != 0 {
				continue
			}
		}
		if r.GreaterEqual != "" {
			n, err := a.Type.TestEndpoint(family, r.GreaterEqual, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterEqual, v)
			}
			if n > 0 {
				continue
			}
		}
		if r.GreaterThan != "" {
			n, err := a.Type.TestEndpoint(family, r.GreaterThan, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterThan, v)
			}
			if n >= 0 {
				continue
			}
		}
		if r.LessEqual != "" {
			n, err := a.Type.TestEndpoint(family, r.LessEqual, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessEqual, v)
			}
			if n < 0 {
				continue
			}
		}
		if r.LessThan != "" {
			n, err := a.Type.TestEndpoint(family, r.LessThan, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessThan, v)
			}
			if n <= 0 {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// IsUnresolved reports whether a is the Affected of a package known affected
// whose range could not be derived (see Unresolved). It is an error when Type
// and Unresolved disagree, or when Unresolved comes with a Range or Fixed.
func (a Affected) IsUnresolved() (bool, error) {
	switch {
	case a.Type == rangeTypes.RangeTypeUnresolved && a.Unresolved == nil:
		return false, errors.Errorf("unexpected affected. expected: %q with unresolved set, actual: unresolved unset", rangeTypes.RangeTypeUnresolved)
	case a.Type != rangeTypes.RangeTypeUnresolved && a.Unresolved != nil:
		return false, errors.Errorf("unexpected affected type with unresolved set. expected: %q, actual: %q", rangeTypes.RangeTypeUnresolved, a.Type)
	case a.Unresolved != nil && (len(a.Range) > 0 || len(a.Fixed) > 0):
		return false, errors.Errorf("unexpected range or fixed with unresolved set. expected: none, actual: range %v, fixed %q", a.Range, a.Fixed)
	default:
		return a.Unresolved != nil, nil
	}
}
