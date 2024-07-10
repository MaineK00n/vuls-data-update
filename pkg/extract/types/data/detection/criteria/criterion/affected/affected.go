package affected

import (
	"cmp"
	"slices"

	"github.com/pkg/errors"

	affectedrange "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
)

type Affected struct {
	Type  affectedrange.RangeType `json:"type,omitempty"`
	Range []affectedrange.Range   `json:"range,omitempty"`
	Fixed []string                `json:"fixed,omitempty"`
}

func (a *Affected) Sort() {
	slices.SortFunc(a.Range, affectedrange.Compare)
	slices.Sort(a.Fixed)
}

func Compare(x, y Affected) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		slices.CompareFunc(x.Range, y.Range, affectedrange.Compare),
		slices.Compare(x.Fixed, y.Fixed),
	)
}

func (a Affected) Filter(v string) (Affected, error) {
	filtered := Affected{Type: a.Type}
	for _, r := range a.Range {
		if r.Equal != "" {
			n, err := a.Type.Compare(r.Equal, v)
			if err != nil {
				return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.Equal, v)
			}
			if n != 0 {
				continue
			}
		}
		if r.GreaterEqual != "" {
			n, err := a.Type.Compare(r.GreaterEqual, v)
			if err != nil {
				return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterEqual, v)
			}
			if n > 0 {
				continue
			}
		}
		if r.GreaterThan != "" {
			n, err := a.Type.Compare(r.GreaterThan, v)
			if err != nil {
				return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterThan, v)
			}
			if n >= 0 {
				continue
			}
		}
		if r.LessEqual != "" {
			n, err := a.Type.Compare(r.LessEqual, v)
			if err != nil {
				return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessEqual, v)
			}
			if n < 0 {
				continue
			}
		}
		if r.LessThan != "" {
			n, err := a.Type.Compare(r.LessThan, v)
			if err != nil {
				return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessThan, v)
			}
			if n <= 0 {
				continue
			}
		}
		filtered.Range = append(filtered.Range, r)
	}
	for _, fixed := range a.Fixed {
		n, err := a.Type.Compare(fixed, v)
		if err != nil {
			return Affected{}, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, fixed, v)
		}
		if n >= 0 {
			filtered.Fixed = append(filtered.Fixed, fixed)
		}
	}
	return filtered, nil
}

func (a Affected) Contains(v string) (bool, error) {
	filtered, err := a.Filter(v)
	if err != nil {
		return false, errors.Wrap(err, "filter affected")
	}
	if len(filtered.Range) > 0 {
		return true, nil
	}
	return false, nil
}
