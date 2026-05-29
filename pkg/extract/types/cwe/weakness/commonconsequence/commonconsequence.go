package commonconsequence

import (
	"cmp"
	"slices"
)

type CommonConsequence struct {
	Scope      []string `json:"scope,omitempty"`  // e.g. "Confidentiality", "Integrity", "Availability"
	Impact     []string `json:"impact,omitempty"` // e.g. "Read Application Data", "DoS: Crash"
	Note       string   `json:"note,omitempty"`
	Likelihood string   `json:"likelihood,omitempty"`
}

func (c *CommonConsequence) Sort() {
	slices.Sort(c.Scope)
	slices.Sort(c.Impact)
}

func Compare(x, y CommonConsequence) int {
	return cmp.Or(
		slices.Compare(x.Scope, y.Scope),
		slices.Compare(x.Impact, y.Impact),
		cmp.Compare(x.Note, y.Note),
		cmp.Compare(x.Likelihood, y.Likelihood),
	)
}
