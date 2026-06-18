package tactic

import (
	"cmp"
	"slices"
)

type Tactic struct {
	Shortname  string   `json:"shortname,omitempty"`
	Techniques []string `json:"techniques,omitempty"` // Technique IDs ("T*") belonging to this tactic (reverse of technique.Tactics)
}

func (t *Tactic) Sort() {
	slices.Sort(t.Techniques)
}

func Compare(x, y Tactic) int {
	return cmp.Or(
		cmp.Compare(x.Shortname, y.Shortname),
		slices.Compare(x.Techniques, y.Techniques),
	)
}
