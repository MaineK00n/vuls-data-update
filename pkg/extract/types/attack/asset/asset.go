package asset

import (
	"cmp"
	"slices"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
)

// Asset represents the kind-specific fields for an ATT&CK Asset
// (STIX x-mitre-asset, ICS only).
type Asset struct {
	Platforms           []string                     `json:"platforms,omitempty"`
	Sectors             []string                     `json:"sectors,omitempty"`
	RelatedAssets       []RelatedAsset               `json:"related_assets,omitempty"`
	TechniquesTargeting []relatedrefTypes.RelatedRef `json:"techniques_targeting,omitempty"` // Technique IDs ("T*") + per-edge description from "targets" rel
}

// RelatedAsset is an embedded entry inside Asset.RelatedAssets.
type RelatedAsset struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Sectors     []string `json:"sectors,omitempty"`
}

func (a *Asset) Sort() {
	slices.Sort(a.Platforms)
	slices.Sort(a.Sectors)
	slices.SortFunc(a.TechniquesTargeting, relatedrefTypes.Compare)
	for i := range a.RelatedAssets {
		slices.Sort(a.RelatedAssets[i].Sectors)
	}
	slices.SortFunc(a.RelatedAssets, CompareRelatedAsset)
}

func Compare(x, y Asset) int {
	return cmp.Or(
		slices.Compare(x.Platforms, y.Platforms),
		slices.Compare(x.Sectors, y.Sectors),
		slices.CompareFunc(x.RelatedAssets, y.RelatedAssets, CompareRelatedAsset),
		slices.CompareFunc(x.TechniquesTargeting, y.TechniquesTargeting, relatedrefTypes.Compare),
	)
}

func CompareRelatedAsset(x, y RelatedAsset) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Description, y.Description),
		slices.Compare(x.Sectors, y.Sectors),
	)
}
