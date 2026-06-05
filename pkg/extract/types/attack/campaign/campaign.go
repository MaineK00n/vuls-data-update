package campaign

import (
	"cmp"
	"slices"
	"time"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Campaign represents a MITRE ATT&CK Campaign (STIX campaign).
type Campaign struct {
	Aliases          []string                           `json:"aliases,omitempty"`
	FirstSeen        time.Time                          `json:"first_seen,omitzero"`
	LastSeen         time.Time                          `json:"last_seen,omitzero"`
	TechniquesUsed   []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	GroupsAttributed []relatedrefTypes.RelatedRef       `json:"groups_attributed,omitempty"` // Group IDs ("G*") + per-edge desc/refs from attributed-to rel
	SoftwaresUsed    []relatedrefTypes.RelatedRef       `json:"softwares_used,omitempty"`    // Software IDs ("S*") + per-edge desc/refs from uses rel
}

func (c *Campaign) Sort() {
	slices.Sort(c.Aliases)
	for i := range c.GroupsAttributed {
		(&c.GroupsAttributed[i]).Sort()
	}
	slices.SortFunc(c.GroupsAttributed, relatedrefTypes.Compare)
	for i := range c.SoftwaresUsed {
		(&c.SoftwaresUsed[i]).Sort()
	}
	slices.SortFunc(c.SoftwaresUsed, relatedrefTypes.Compare)
	for i := range c.TechniquesUsed {
		(&c.TechniquesUsed[i]).Sort()
	}
	slices.SortFunc(c.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Campaign) int {
	return cmp.Or(
		slices.Compare(x.Aliases, y.Aliases),
		x.FirstSeen.Compare(y.FirstSeen),
		x.LastSeen.Compare(y.LastSeen),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.CompareFunc(x.GroupsAttributed, y.GroupsAttributed, relatedrefTypes.Compare),
		slices.CompareFunc(x.SoftwaresUsed, y.SoftwaresUsed, relatedrefTypes.Compare),
	)
}
