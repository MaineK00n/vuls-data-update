package modeofintroduction

import (
	"cmp"
	"slices"

	customphaseTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/customphase"
)

type ModeOfIntroduction struct {
	// Deprecated: an introduction may name several phases since CWE 5.0, so
	// they are in Phases; Phase is only set in data extracted before that.
	Phase        string                         `json:"phase,omitempty"`
	Phases       []string                       `json:"phases,omitempty"`
	CustomPhases []customphaseTypes.CustomPhase `json:"custom_phases,omitempty"`
	Notes        []string                       `json:"notes,omitempty"`
}

func (m *ModeOfIntroduction) Sort() {
	slices.Sort(m.Phases)
	slices.SortFunc(m.CustomPhases, customphaseTypes.Compare)
	slices.Sort(m.Notes)
}

func Compare(x, y ModeOfIntroduction) int {
	return cmp.Or(
		cmp.Compare(x.Phase, y.Phase),
		slices.Compare(x.Phases, y.Phases),
		slices.CompareFunc(x.CustomPhases, y.CustomPhases, customphaseTypes.Compare),
		slices.Compare(x.Notes, y.Notes),
	)
}
