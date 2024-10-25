package detection

import (
	"cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
)

type Detection struct {
	Ecosystem ecosystemTypes.Ecosystem `json:"ecosystem,omitempty"`
	Criteria  criteriaTypes.Criteria   `json:"criteria,omitempty"`
}

func (d *Detection) Sort() {
	(&d.Criteria).Sort()
}

func Compare(x, y Detection) int {
	return cmp.Or(
		ecosystemTypes.Compare(x.Ecosystem, y.Ecosystem),
		criteriaTypes.Compare(x.Criteria, y.Criteria),
	)
}
