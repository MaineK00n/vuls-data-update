package detectionmethod

import "cmp"

type DetectionMethod struct {
	DetectionMethodID  string `json:"detection_method_id,omitempty"`
	Method             string `json:"method,omitempty"`
	Description        string `json:"description,omitempty"`
	Effectiveness      string `json:"effectiveness,omitempty"`
	EffectivenessNotes string `json:"effectiveness_notes,omitempty"`
}

func Compare(x, y DetectionMethod) int {
	return cmp.Or(
		cmp.Compare(x.DetectionMethodID, y.DetectionMethodID),
		cmp.Compare(x.Method, y.Method),
		cmp.Compare(x.Description, y.Description),
		cmp.Compare(x.Effectiveness, y.Effectiveness),
		cmp.Compare(x.EffectivenessNotes, y.EffectivenessNotes),
	)
}
