package tactic

import "cmp"

type Tactic struct {
	Shortname string `json:"shortname,omitempty"`
}

func Compare(x, y Tactic) int {
	return cmp.Compare(x.Shortname, y.Shortname)
}
