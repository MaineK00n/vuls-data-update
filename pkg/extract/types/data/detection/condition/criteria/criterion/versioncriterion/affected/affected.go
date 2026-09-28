package affected

import (
	"cmp"
	stderrors "errors"
	"fmt"
	"slices"

	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	ipsVersion "github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/version/ips"
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
			return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}}
		}
		if r.Equal != "" {
			n, err := testPattern(a.Type, family, r.Equal, v)
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
			n, err := testPattern(a.Type, family, r.GreaterEqual, v)
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
			n, err := testPattern(a.Type, family, r.GreaterThan, v)
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
			n, err := testPattern(a.Type, family, r.LessEqual, v)
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
			n, err := testPattern(a.Type, family, r.LessThan, v)
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

// testPattern tells where the version v falls against pattern, the string
// an operator of a Range carries, under t: -1 before it, 0 on it, +1 after
// it. For every type but one the pattern is a full version and this is the
// sign of t.CompareVersions(pattern, v), with its errors. A solaris-ips
// pattern names only the components it wants compared (a level such as
// 11.4-11.4.94), so it is not put through the version order: ips.Pattern.Test
// answers the same question, skipping a component the pattern omits; one it
// names but v lacks cannot be tested and is a *rangeTypes.CompareError, so
// the range is a non-match. CompareVersions itself stays an order between two
// versions.
func testPattern(t rangeTypes.RangeType, family ecosystemTypes.Ecosystem, pattern, v string) (int, error) {
	switch t {
	case rangeTypes.RangeTypeSolarisIPS:
		p, err := ipsVersion.NewPattern(pattern)
		if err != nil {
			return 0, &rangeTypes.CompareError{Err: &rangeTypes.NewVersionError{RangeType: t, Version: pattern, Err: err}}
		}
		w, err := ipsVersion.NewVersion(v)
		if err != nil {
			return 0, &rangeTypes.CompareError{Err: &rangeTypes.NewVersionError{RangeType: t, Version: v, Err: err}}
		}
		n, err := p.Test(w)
		if err != nil {
			return 0, &rangeTypes.CompareError{Err: &rangeTypes.CannotCompareError{Reason: fmt.Sprintf("%s. pattern: %q, v: %q", err, pattern, v)}}
		}
		return n, nil
	default:
		return t.CompareVersions(family, pattern, v)
	}
}
