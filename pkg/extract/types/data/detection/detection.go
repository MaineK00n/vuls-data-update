package detection

import (
	"cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	scopeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/scope"
)

type Detection struct {
	Scope    scopeTypes.Scope       `json:"scope,omitempty"`
	Criteria criteriaTypes.Criteria `json:"criteria,omitempty"`
}

func (d *Detection) Sort() {
	(&d.Criteria).Sort()
}

func Compare(x, y Detection) int {
	return cmp.Or(
		scopeTypes.Compare(x.Scope, y.Scope),
		criteriaTypes.Compare(x.Criteria, y.Criteria),
	)
}
