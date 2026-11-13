package alternateterm

import (
	"cmp"
	"slices"
)

type AlternateTerm struct {
	Term        string   `json:"term,omitempty"`
	Roles       []string `json:"roles,omitempty"` // e.g. "Acronym", "Attack-Focused" (CWE 5.0)
	Description string   `json:"description,omitempty"`
}

func (a *AlternateTerm) Sort() {
	slices.Sort(a.Roles)
}

func Compare(x, y AlternateTerm) int {
	return cmp.Or(
		cmp.Compare(x.Term, y.Term),
		slices.Compare(x.Roles, y.Roles),
		cmp.Compare(x.Description, y.Description),
	)
}
