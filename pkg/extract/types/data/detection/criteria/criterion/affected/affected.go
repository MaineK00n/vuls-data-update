package affected

import (
	"cmp"
	"slices"

	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
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
		cmp.Compare(x.Type, y.Type),
		slices.CompareFunc(x.Range, y.Range, rangeTypes.Compare),
		slices.Compare(x.Fixed, y.Fixed),
	)
}

func (a Affected) Accept(ecosystem ecosystemTypes.Ecosystem, v string) (bool, error) {
	for _, r := range a.Range {
		if r.Equal != "" {
			n, err := a.Type.Compare(ecosystem, r.Equal, v)
			if err != nil {
				var compareErr *rangeTypes.CompareError
				if errors.As(err, &compareErr) {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.Equal, v)
			}
			if n != 0 {
				continue
			}
		}
		if r.GreaterEqual != "" {
			n, err := a.Type.Compare(ecosystem, r.GreaterEqual, v)
			if err != nil {
				var compareErr *rangeTypes.CompareError
				if errors.As(err, &compareErr) {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterEqual, v)
			}
			if n > 0 {
				continue
			}
		}
		if r.GreaterThan != "" {
			n, err := a.Type.Compare(ecosystem, r.GreaterThan, v)
			if err != nil {
				var compareErr *rangeTypes.CompareError
				if errors.As(err, &compareErr) {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterThan, v)
			}
			if n >= 0 {
				continue
			}
		}
		if r.LessEqual != "" {
			n, err := a.Type.Compare(ecosystem, r.LessEqual, v)
			if err != nil {
				var compareErr *rangeTypes.CompareError
				if errors.As(err, &compareErr) {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessEqual, v)
			}
			if n < 0 {
				continue
			}
		}
		if r.LessThan != "" {
			n, err := a.Type.Compare(ecosystem, r.LessThan, v)
			if err != nil {
				var compareErr *rangeTypes.CompareError
				if errors.As(err, &compareErr) {
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
