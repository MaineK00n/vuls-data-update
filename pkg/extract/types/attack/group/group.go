package group

import (
	"cmp"
	"slices"

	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Group represents a MITRE ATT&CK Group (STIX intrusion-set).
type Group struct {
	Aliases        []string                           `json:"aliases,omitempty"`
	TechniquesUsed []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	SoftwaresUsed  []string                           `json:"softwares_used,omitempty"` // Software IDs ("S*")
}

func (g *Group) Sort() {
	slices.Sort(g.Aliases)
	slices.Sort(g.SoftwaresUsed)
	slices.SortFunc(g.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Group) int {
	return cmp.Or(
		slices.Compare(x.Aliases, y.Aliases),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.Compare(x.SoftwaresUsed, y.SoftwaresUsed),
	)
}
