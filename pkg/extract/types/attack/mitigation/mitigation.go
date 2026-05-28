package mitigation

import "slices"

// Mitigation represents the kind-specific fields for an ATT&CK Mitigation
// (STIX course-of-action).
type Mitigation struct {
	TechniquesMitigated []string `json:"techniques_mitigated,omitempty"` // Technique IDs ("T*")
}

func (m *Mitigation) Sort() {
	slices.Sort(m.TechniquesMitigated)
}

func Compare(x, y Mitigation) int {
	return slices.Compare(x.TechniquesMitigated, y.TechniquesMitigated)
}
