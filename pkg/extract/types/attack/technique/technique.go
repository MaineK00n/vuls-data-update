package technique

import (
	"cmp"
	"slices"

	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
)

type Technique struct {
	Platforms            []string                   `json:"platforms,omitempty"`
	Tactics              []string                   `json:"tactics,omitempty"` // tactic shortnames (e.g. "initial-access")
	IsSubtechnique       bool                       `json:"is_subtechnique,omitempty"`
	Parent               string                     `json:"parent,omitempty"` // Subtechnique parent Technique ID
	Detection            string                     `json:"detection,omitempty"`
	DataSources          []string                   `json:"data_sources,omitempty"`
	Mitigations          []string                   `json:"mitigations,omitempty"` // Mitigation IDs ("M*")
	Procedures           []procedureTypes.Procedure `json:"procedures,omitempty"`  // Attacker (G*/S*/C*) → use description
	PermissionsRequired  []string                   `json:"permissions_required,omitempty"`
	EffectivePermissions []string                   `json:"effective_permissions,omitempty"`
	DefenseBypassed      []string                   `json:"defense_bypassed,omitempty"`
	ImpactType           []string                   `json:"impact_type,omitempty"`
	NetworkRequirements  bool                       `json:"network_requirements,omitempty"`
	RemoteSupport        bool                       `json:"remote_support,omitempty"`
}

func (t *Technique) Sort() {
	slices.Sort(t.Platforms)
	slices.Sort(t.Tactics)
	slices.Sort(t.DataSources)
	slices.Sort(t.Mitigations)
	slices.Sort(t.PermissionsRequired)
	slices.Sort(t.EffectivePermissions)
	slices.Sort(t.DefenseBypassed)
	slices.Sort(t.ImpactType)
	slices.SortFunc(t.Procedures, procedureTypes.Compare)
}

func Compare(x, y Technique) int {
	return cmp.Or(
		slices.Compare(x.Platforms, y.Platforms),
		slices.Compare(x.Tactics, y.Tactics),
		cmp.Compare(x.Parent, y.Parent),
		cmp.Compare(x.Detection, y.Detection),
		slices.Compare(x.DataSources, y.DataSources),
		slices.Compare(x.Mitigations, y.Mitigations),
		slices.CompareFunc(x.Procedures, y.Procedures, procedureTypes.Compare),
		slices.Compare(x.PermissionsRequired, y.PermissionsRequired),
		slices.Compare(x.EffectivePermissions, y.EffectivePermissions),
		slices.Compare(x.DefenseBypassed, y.DefenseBypassed),
		slices.Compare(x.ImpactType, y.ImpactType),
	)
}
