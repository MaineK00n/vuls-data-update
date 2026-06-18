package group

import (
	"cmp"
	"slices"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Group represents a MITRE ATT&CK Group (STIX intrusion-set).
type Group struct {
	Aliases             []string                           `json:"aliases,omitempty"`
	TechniquesUsed      []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	SoftwaresUsed       []relatedrefTypes.RelatedRef       `json:"softwares_used,omitempty"`       // Software IDs ("S*") + per-edge desc/refs from uses rel
	CampaignsAttributed []relatedrefTypes.RelatedRef       `json:"campaigns_attributed,omitempty"` // Campaign IDs ("C*") + per-edge desc/refs (reverse of campaign attributed-to)
}

func (g *Group) Sort() {
	slices.Sort(g.Aliases)
	for i := range g.SoftwaresUsed {
		(&g.SoftwaresUsed[i]).Sort()
	}
	slices.SortFunc(g.SoftwaresUsed, relatedrefTypes.Compare)
	for i := range g.CampaignsAttributed {
		(&g.CampaignsAttributed[i]).Sort()
	}
	slices.SortFunc(g.CampaignsAttributed, relatedrefTypes.Compare)
	for i := range g.TechniquesUsed {
		(&g.TechniquesUsed[i]).Sort()
	}
	slices.SortFunc(g.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Group) int {
	return cmp.Or(
		slices.Compare(x.Aliases, y.Aliases),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.CompareFunc(x.SoftwaresUsed, y.SoftwaresUsed, relatedrefTypes.Compare),
		slices.CompareFunc(x.CampaignsAttributed, y.CampaignsAttributed, relatedrefTypes.Compare),
	)
}
