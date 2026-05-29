package alternateterm

import "cmp"

type AlternateTerm struct {
	Term        string `json:"term,omitempty"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y AlternateTerm) int {
	return cmp.Or(
		cmp.Compare(x.Term, y.Term),
		cmp.Compare(x.Description, y.Description),
	)
}
