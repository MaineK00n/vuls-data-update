package potentialmitigation

import (
	"cmp"
	"slices"

	customphaseTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/customphase"
)

type PotentialMitigation struct {
	MitigationID       string                         `json:"mitigation_id,omitempty"`
	Phases             []string                       `json:"phases,omitempty"`
	CustomPhases       []customphaseTypes.CustomPhase `json:"custom_phases,omitempty"` // CWE 5.0
	Descriptions       []string                       `json:"descriptions,omitempty"`
	Strategy           string                         `json:"strategy,omitempty"`
	Effectiveness      string                         `json:"effectiveness,omitempty"`
	EffectivenessNotes string                         `json:"effectiveness_notes,omitempty"`
}

func (m *PotentialMitigation) Sort() {
	slices.Sort(m.Phases)
	slices.SortFunc(m.CustomPhases, customphaseTypes.Compare)
	slices.Sort(m.Descriptions)
}

func Compare(x, y PotentialMitigation) int {
	return cmp.Or(
		cmp.Compare(x.MitigationID, y.MitigationID),
		slices.Compare(x.Phases, y.Phases),
		slices.CompareFunc(x.CustomPhases, y.CustomPhases, customphaseTypes.Compare),
		slices.Compare(x.Descriptions, y.Descriptions),
		cmp.Compare(x.Strategy, y.Strategy),
		cmp.Compare(x.Effectiveness, y.Effectiveness),
		cmp.Compare(x.EffectivenessNotes, y.EffectivenessNotes),
	)
}
