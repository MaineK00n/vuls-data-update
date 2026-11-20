package detectionmethod

import (
	"cmp"
	"slices"

	customphaseTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/customphase"
)

type DetectionMethod struct {
	DetectionMethodID  string                         `json:"detection_method_id,omitempty"`
	Method             string                         `json:"method,omitempty"`
	Phases             []string                       `json:"phases,omitempty"`        // CWE 5.0
	CustomPhases       []customphaseTypes.CustomPhase `json:"custom_phases,omitempty"` // CWE 5.0
	Description        string                         `json:"description,omitempty"`
	Effectiveness      string                         `json:"effectiveness,omitempty"`
	EffectivenessNotes string                         `json:"effectiveness_notes,omitempty"`
}

func (m *DetectionMethod) Sort() {
	slices.Sort(m.Phases)
	slices.SortFunc(m.CustomPhases, customphaseTypes.Compare)
}

func Compare(x, y DetectionMethod) int {
	return cmp.Or(
		cmp.Compare(x.DetectionMethodID, y.DetectionMethodID),
		cmp.Compare(x.Method, y.Method),
		slices.Compare(x.Phases, y.Phases),
		slices.CompareFunc(x.CustomPhases, y.CustomPhases, customphaseTypes.Compare),
		cmp.Compare(x.Description, y.Description),
		cmp.Compare(x.Effectiveness, y.Effectiveness),
		cmp.Compare(x.EffectivenessNotes, y.EffectivenessNotes),
	)
}
