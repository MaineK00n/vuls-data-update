package mitigation

import (
	"slices"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
)

// Mitigation represents the kind-specific fields for an ATT&CK Mitigation
// (STIX course-of-action).
type Mitigation struct {
	TechniquesMitigated []relatedrefTypes.RelatedRef `json:"techniques_mitigated,omitempty"` // Technique IDs ("T*") + per-edge "Use" description from mitigates rel
}

func (m *Mitigation) Sort() {
	for i := range m.TechniquesMitigated {
		(&m.TechniquesMitigated[i]).Sort()
	}
	slices.SortFunc(m.TechniquesMitigated, relatedrefTypes.Compare)
}

func Compare(x, y Mitigation) int {
	return slices.CompareFunc(x.TechniquesMitigated, y.TechniquesMitigated, relatedrefTypes.Compare)
}
