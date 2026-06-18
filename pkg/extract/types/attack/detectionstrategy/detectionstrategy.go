package detectionstrategy

import (
	"cmp"
	"slices"

	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
)

// DetectionStrategy represents the kind-specific fields for an ATT&CK
// Detection Strategy (STIX x-mitre-detection-strategy).
type DetectionStrategy struct {
	Analytics          []string                     `json:"analytics,omitempty"`           // Analytic IDs ("AN*")
	TechniquesDetected []relatedrefTypes.RelatedRef `json:"techniques_detected,omitempty"` // Technique IDs ("T*") + per-edge description from detects rel
}

func (d *DetectionStrategy) Sort() {
	slices.Sort(d.Analytics)
	for i := range d.TechniquesDetected {
		(&d.TechniquesDetected[i]).Sort()
	}
	slices.SortFunc(d.TechniquesDetected, relatedrefTypes.Compare)
}

func Compare(x, y DetectionStrategy) int {
	return cmp.Or(
		slices.Compare(x.Analytics, y.Analytics),
		slices.CompareFunc(x.TechniquesDetected, y.TechniquesDetected, relatedrefTypes.Compare),
	)
}
