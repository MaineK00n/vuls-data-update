package campaign

import (
	"cmp"
	"slices"
	"time"

	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Campaign represents a MITRE ATT&CK Campaign (STIX campaign).
type Campaign struct {
	Aliases          []string                           `json:"aliases,omitempty"`
	FirstSeen        time.Time                          `json:"first_seen,omitzero"`
	LastSeen         time.Time                          `json:"last_seen,omitzero"`
	TechniquesUsed   []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	GroupsAttributed []string                           `json:"groups_attributed,omitempty"` // Group IDs ("G*")
	SoftwaresUsed    []string                           `json:"softwares_used,omitempty"`    // Software IDs ("S*")
}

func (c *Campaign) Sort() {
	slices.Sort(c.Aliases)
	slices.Sort(c.GroupsAttributed)
	slices.Sort(c.SoftwaresUsed)
	slices.SortFunc(c.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Campaign) int {
	return cmp.Or(
		slices.Compare(x.Aliases, y.Aliases),
		x.FirstSeen.Compare(y.FirstSeen),
		x.LastSeen.Compare(y.LastSeen),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.Compare(x.GroupsAttributed, y.GroupsAttributed),
		slices.Compare(x.SoftwaresUsed, y.SoftwaresUsed),
	)
}
