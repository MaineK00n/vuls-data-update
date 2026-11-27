package relatedweakness

import (
	"cmp"
	"slices"

	dimensionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/dimension"
)

type RelatedWeakness struct {
	Nature     string                     `json:"nature,omitempty"`
	CWEID      string                     `json:"cweid,omitempty"`
	ViewID     string                     `json:"view_id,omitempty"`
	Ordinal    string                     `json:"ordinal,omitempty"`    // "Primary" | "Resultant"
	ChainID    string                     `json:"chain_id,omitempty"`   // Chain relationship member ID
	Dimensions []dimensionTypes.Dimension `json:"dimensions,omitempty"` // dimensions in which the related weakness differs (CWE 5.0)
}

func (r *RelatedWeakness) Sort() {
	slices.SortFunc(r.Dimensions, dimensionTypes.Compare)
}

func Compare(x, y RelatedWeakness) int {
	return cmp.Or(
		cmp.Compare(x.Nature, y.Nature),
		cmp.Compare(x.CWEID, y.CWEID),
		cmp.Compare(x.ViewID, y.ViewID),
		cmp.Compare(x.Ordinal, y.Ordinal),
		cmp.Compare(x.ChainID, y.ChainID),
		slices.CompareFunc(x.Dimensions, y.Dimensions, dimensionTypes.Compare),
	)
}
