package modeofintroduction

import (
	"cmp"
	"slices"
)

type ModeOfIntroduction struct {
	Phase string   `json:"phase"`
	Notes []string `json:"notes,omitempty"`
}

func (m *ModeOfIntroduction) Sort() {
	slices.Sort(m.Notes)
}

func Compare(x, y ModeOfIntroduction) int {
	return cmp.Or(
		cmp.Compare(x.Phase, y.Phase),
		slices.Compare(x.Notes, y.Notes),
	)
}
