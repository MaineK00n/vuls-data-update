package software

import (
	"cmp"
	"slices"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
)

// Software represents a MITRE ATT&CK Software (STIX malware or tool).
type Software struct {
	Type           string                             `json:"type,omitempty"` // "malware" | "tool"
	Aliases        []string                           `json:"aliases,omitempty"`
	Platforms      []string                           `json:"platforms,omitempty"`
	TechniquesUsed []techniqueusedTypes.TechniqueUsed `json:"techniques_used,omitempty"`
	GroupsUsing    []relatedrefTypes.RelatedRef       `json:"groups_using,omitempty"`    // Group IDs ("G*") + per-edge desc/refs (reverse of group uses software)
	CampaignsUsing []relatedrefTypes.RelatedRef       `json:"campaigns_using,omitempty"` // Campaign IDs ("C*") + per-edge desc/refs (reverse of campaign uses software)
}

func (s *Software) Sort() {
	slices.Sort(s.Aliases)
	slices.Sort(s.Platforms)
	for i := range s.GroupsUsing {
		(&s.GroupsUsing[i]).Sort()
	}
	slices.SortFunc(s.GroupsUsing, relatedrefTypes.Compare)
	for i := range s.CampaignsUsing {
		(&s.CampaignsUsing[i]).Sort()
	}
	slices.SortFunc(s.CampaignsUsing, relatedrefTypes.Compare)
	for i := range s.TechniquesUsed {
		(&s.TechniquesUsed[i]).Sort()
	}
	slices.SortFunc(s.TechniquesUsed, techniqueusedTypes.Compare)
}

func Compare(x, y Software) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		slices.Compare(x.Aliases, y.Aliases),
		slices.Compare(x.Platforms, y.Platforms),
		slices.CompareFunc(x.TechniquesUsed, y.TechniquesUsed, techniqueusedTypes.Compare),
		slices.CompareFunc(x.GroupsUsing, y.GroupsUsing, relatedrefTypes.Compare),
		slices.CompareFunc(x.CampaignsUsing, y.CampaignsUsing, relatedrefTypes.Compare),
	)
}
