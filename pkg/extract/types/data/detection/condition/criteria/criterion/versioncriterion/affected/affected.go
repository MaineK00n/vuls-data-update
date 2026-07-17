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
	)
}

func (a Affected) Accept(family ecosystemTypes.Ecosystem, v string) (bool, error) {
	for _, r := range a.Range {
		// A Range element with no endpoints expresses nothing — malformed
		// data (no extractor produces one; schema validation is the hard
		// gate) or a newer range type whose constraints live in JSON fields
		// this build's unmarshal drops. Either way the criterion cannot be
		// evaluated: report it as a non-fatal empty-range warning rather
		// than aborting detection in the field. Whether a Type is evaluable
		// is otherwise derived from CompareVersions itself on the bound
		// comparisons below: anything it has no comparator for (unset,
		// newer-data values, comparator-less vocabulary debt like pacman)
		// answers with *UnsupportedRangeTypeError and is reported as a
		// non-fatal *warning.UnevaluableError.
		if r == (rangeTypes.Range{}) {
			return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange, Cause: string(a.Type)}}
		}
		if r.Equal != "" {
			n, err := a.Type.CompareVersions(family, r.Equal, v)
			if err != nil {
				if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
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
			n, err := a.Type.CompareVersions(family, r.GreaterEqual, v)
			if err != nil {
				if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
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
			n, err := a.Type.CompareVersions(family, r.GreaterThan, v)
			if err != nil {
				if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
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
			n, err := a.Type.CompareVersions(family, r.LessEqual, v)
			if err != nil {
				if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
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
			n, err := a.Type.CompareVersions(family, r.LessThan, v)
			if err != nil {
				if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
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
