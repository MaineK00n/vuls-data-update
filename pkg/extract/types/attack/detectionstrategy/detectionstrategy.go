package detectionstrategy

import (
	"cmp"
	"slices"
)

// DetectionStrategy represents the kind-specific fields for an ATT&CK
// Detection Strategy (STIX x-mitre-detection-strategy).
type DetectionStrategy struct {
	Analytics          []string `json:"analytics,omitempty"`           // Analytic IDs ("AN*")
	TechniquesDetected []string `json:"techniques_detected,omitempty"` // Technique IDs ("T*")
}

func (d *DetectionStrategy) Sort() {
	slices.Sort(d.Analytics)
	slices.Sort(d.TechniquesDetected)
}

func Compare(x, y DetectionStrategy) int {
	return cmp.Or(
		slices.Compare(x.Analytics, y.Analytics),
		slices.Compare(x.TechniquesDetected, y.TechniquesDetected),
	)
}
