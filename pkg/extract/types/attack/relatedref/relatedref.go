package relatedref

import "cmp"

// RelatedRef is a reference to another ATT&CK record paired with the
// per-edge description carried by the STIX relationship object. Used
// wherever the relationship's description is meaningful for end users
// (the "Use" column shown on the ATT&CK web UI):
//
//   - mitigates  — both Mitigation.TechniquesMitigated and Technique.Mitigations
//   - detects    — both DetectionStrategy.TechniquesDetected and Technique.DetectionStrategies
//   - targets    — both Asset.TechniquesTargeting and Technique.AssetsTargeted
//
// The role of ID (Technique vs Mitigation vs DetectionStrategy vs
// Asset) is given by the enclosing field name. Structural-only
// relationships (subtechnique-of, attributed-to) stay as []string
// because their relationship objects carry no description on
// ATT&CK's web view.
type RelatedRef struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y RelatedRef) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Description, y.Description),
	)
}
