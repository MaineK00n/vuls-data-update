package software

import (
	"cmp"
	"slices"

	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Software represents a MITRE ATT&CK Software (STIX malware or tool).
type Software struct {
	Type           string                             `json:"type,omitempty"` // "malware" | "tool"
	Aliases        []string                           `json:"aliases,omitempty"`
	Platforms      []string                           `json:"platforms,omitempty"`
	TechniquesUsed []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	GroupsUsing    []string                           `json:"groups_using,omitempty"` // Group IDs ("G*")
}

func (s *Software) Sort() {
	slices.Sort(s.Aliases)
	slices.Sort(s.Platforms)
	slices.Sort(s.GroupsUsing)
	slices.SortFunc(s.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Software) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		slices.Compare(x.Aliases, y.Aliases),
		slices.Compare(x.Platforms, y.Platforms),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.Compare(x.GroupsUsing, y.GroupsUsing),
	)
}
