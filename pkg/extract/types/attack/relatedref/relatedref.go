package relatedref

import (
	"cmp"
	"slices"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

// RelatedRef is a reference to another ATT&CK record paired with the
// per-edge description and citations carried by the STIX relationship
// object. Used wherever the relationship's description or
// external_references are meaningful for end users (the "Use" and
// citation columns shown on the ATT&CK web UI):
//
//   - mitigates       — Mitigation.TechniquesMitigated, Technique.Mitigations
//   - detects         — DetectionStrategy.TechniquesDetected, Technique.DetectionStrategies
//   - targets         — Asset.TechniquesTargeting, Technique.AssetsTargeted
//   - uses (G↔S/C↔S)  — Group/Campaign.SoftwaresUsed, Software.GroupsUsing/CampaignsUsing
//   - attributed-to   — Campaign.GroupsAttributed, Group.CampaignsAttributed
//
// The role of ID (Technique vs Mitigation vs DetectionStrategy vs
// Asset vs Software vs Group vs Campaign) is given by the enclosing
// field name. Structural-only relationships (subtechnique-of) stay
// as []string because the relationship object carries no description
// or refs there.
type RelatedRef struct {
	ID          string                     `json:"id"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"` // per-edge citations from STIX relationship.external_references
}

func (r *RelatedRef) Sort() {
	slices.SortFunc(r.References, referenceTypes.Compare)
}

func Compare(x, y RelatedRef) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
	)
}
