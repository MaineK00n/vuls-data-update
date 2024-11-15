package detection

import (
	"cmp"
	"slices"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Detection struct {
	Ecosystem  ecosystemTypes.Ecosystem   `json:"ecosystem,omitempty"`
	Conditions []conditionTypes.Condition `json:"conditions,omitempty"`
}

func (d *Detection) Sort() {
	for i := range d.Conditions {
		(&d.Conditions[i]).Sort()
	}
	slices.SortFunc(d.Conditions, conditionTypes.Compare)
}

func Compare(x, y Detection) int {
	return cmp.Or(
		cmp.Compare(x.Ecosystem, y.Ecosystem),
		slices.CompareFunc(x.Conditions, y.Conditions, conditionTypes.Compare),
	)
}
