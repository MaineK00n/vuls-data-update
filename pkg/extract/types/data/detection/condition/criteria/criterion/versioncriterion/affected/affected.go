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
	// The declared Unknown vocabulary value is normal data ("the source
	// declared a constraint we could not translate", not "no constraint")
	// and quietly refuses to match — this also closes the all-empty-Range
	// match-all path below, mirroring cpecriterion/range.
	if a.Type == rangeTypes.RangeTypeUnknown {
		return false, nil
	}
	// Whether a Type is evaluable is derived from CompareVersions itself —
	// its default branch answers anything it has no comparator for (unset,
	// newer-data values, and comparator-less vocabulary debt like pacman)
	// with *UnsupportedRangeTypeError, which the bound comparisons below
	// classify into a non-fatal *warning.UnevaluableError. The all-empty
	// Range element is the one path that never invokes CompareVersions and
	// would fall through to the unconditional match-all — matching every
	// version with a type that can evaluate nothing, and "all-empty" cannot
	// even be trusted for newer types (their constraints may live in JSON
	// fields this build's unmarshal silently drops). So probe: compare v
	// against itself purely to learn whether a comparator exists. A parse
	// failure (*CompareError without the unsupported cause) keeps the
	// documented match-all semantics — no bounds accept even an unparseable
	// v.
	if slices.Contains(a.Range, rangeTypes.Range{}) {
		if _, err := a.Type.CompareVersions(family, v, v); err != nil {
			if ue, ok := stderrors.AsType[*rangeTypes.UnsupportedRangeTypeError](err); ok {
				return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
			}
			if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); !ok {
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, v, v)
			}
		}
	}
	for _, r := range a.Range {
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
