package affected

import (
	"cmp"
	"slices"

	affectedrange "github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/affected/range"
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
	if c := cmp.Compare(x.Type, y.Type); c != 0 {
		return c
	}
	if c := slices.CompareFunc(x.Range, y.Range, affectedrange.Compare); c != 0 {
		return c
	}
	return slices.Compare(x.Fixed, y.Fixed)
}

func (a Affected) LessThan(v string) (bool, error) {
	// TODO:
	return false, nil
}
