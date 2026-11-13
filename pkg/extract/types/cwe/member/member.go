package member

import (
	"cmp"
	"slices"

	dimensionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/dimension"
)

// Member represents a CWE that is a member of a Category or a View.
type Member struct {
	CWEID      string                     `json:"cweid"`
	ViewID     string                     `json:"view_id,omitempty"`
	Dimensions []dimensionTypes.Dimension `json:"dimensions,omitempty"` // CWE 5.0
}

func (m *Member) Sort() {
	slices.SortFunc(m.Dimensions, dimensionTypes.Compare)
}

func Compare(x, y Member) int {
	return cmp.Or(
		cmp.Compare(x.CWEID, y.CWEID),
		cmp.Compare(x.ViewID, y.ViewID),
		slices.CompareFunc(x.Dimensions, y.Dimensions, dimensionTypes.Compare),
	)
}
