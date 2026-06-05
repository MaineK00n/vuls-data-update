package technique

import (
	"cmp"
	"slices"

	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
)

type Technique struct {
	Platforms            []string                       `json:"platforms,omitempty"`
	Tactics              []string                       `json:"tactics,omitempty"` // tactic shortnames (e.g. "initial-access")
	IsSubtechnique       bool                           `json:"is_subtechnique,omitempty"`
	Parent               string                         `json:"parent,omitempty"` // Subtechnique parent Technique ID
	Detection            string                         `json:"detection,omitempty"`
	DataSources          []string                       `json:"data_sources,omitempty"`
	Mitigations          []relatedrefTypes.RelatedRef   `json:"mitigations,omitempty"` // Mitigation IDs ("M*") + per-edge "Use" description from mitigates rel
	Procedures           []procedureTypes.Procedure     `json:"procedures,omitempty"`  // Attacker (G*/S*/C*) → use description
	PermissionsRequired  []string                       `json:"permissions_required,omitempty"`
	EffectivePermissions []string                       `json:"effective_permissions,omitempty"`
	DefenseBypassed      []string                       `json:"defense_bypassed,omitempty"`
	ImpactType           []string                       `json:"impact_type,omitempty"`
	NetworkRequirements  bool                           `json:"network_requirements,omitempty"`
	RemoteSupport        bool                           `json:"remote_support,omitempty"`
	Subtechniques        []string                       `json:"subtechniques,omitempty"`        // Technique IDs ("T*.*") that are sub-techniques of this one (reverse of Parent)
	AssetsTargeted       []relatedrefTypes.RelatedRef   `json:"assets_targeted,omitempty"`      // Asset IDs ("A*") + per-edge description from "targets" rel
	DetectionStrategies  []relatedrefTypes.RelatedRef   `json:"detection_strategies,omitempty"` // DetectionStrategy IDs ("DET*") + per-edge description from "detects" rel
}

func (t *Technique) Sort() {
	slices.Sort(t.Platforms)
	slices.Sort(t.Tactics)
	slices.Sort(t.DataSources)
	slices.SortFunc(t.Mitigations, relatedrefTypes.Compare)
	slices.Sort(t.PermissionsRequired)
	slices.Sort(t.EffectivePermissions)
	slices.Sort(t.DefenseBypassed)
	slices.Sort(t.ImpactType)
	slices.Sort(t.Subtechniques)
	slices.SortFunc(t.AssetsTargeted, relatedrefTypes.Compare)
	slices.SortFunc(t.DetectionStrategies, relatedrefTypes.Compare)
	slices.SortFunc(t.Procedures, procedureTypes.Compare)
}

func Compare(x, y Technique) int {
	return cmp.Or(
		slices.Compare(x.Platforms, y.Platforms),
		slices.Compare(x.Tactics, y.Tactics),
		func() int {
			switch {
			case !x.IsSubtechnique && y.IsSubtechnique:
				return -1
			case x.IsSubtechnique && !y.IsSubtechnique:
				return +1
			default:
				return 0
			}
		}(),
		cmp.Compare(x.Parent, y.Parent),
		cmp.Compare(x.Detection, y.Detection),
		slices.Compare(x.DataSources, y.DataSources),
		slices.CompareFunc(x.Mitigations, y.Mitigations, relatedrefTypes.Compare),
		slices.CompareFunc(x.Procedures, y.Procedures, procedureTypes.Compare),
		slices.Compare(x.PermissionsRequired, y.PermissionsRequired),
		slices.Compare(x.EffectivePermissions, y.EffectivePermissions),
		slices.Compare(x.DefenseBypassed, y.DefenseBypassed),
		slices.Compare(x.ImpactType, y.ImpactType),
		func() int {
			switch {
			case !x.NetworkRequirements && y.NetworkRequirements:
				return -1
			case x.NetworkRequirements && !y.NetworkRequirements:
				return +1
			default:
				return 0
			}
		}(),
		func() int {
			switch {
			case !x.RemoteSupport && y.RemoteSupport:
				return -1
			case x.RemoteSupport && !y.RemoteSupport:
				return +1
			default:
				return 0
			}
		}(),
		slices.Compare(x.Subtechniques, y.Subtechniques),
		slices.CompareFunc(x.AssetsTargeted, y.AssetsTargeted, relatedrefTypes.Compare),
		slices.CompareFunc(x.DetectionStrategies, y.DetectionStrategies, relatedrefTypes.Compare),
	)
}
