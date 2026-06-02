package member

import "cmp"

// Member represents a CWE that is a member of a Category or a View.
type Member struct {
	CWEID  string `json:"cweid"`
	ViewID string `json:"view_id,omitempty"`
}

func Compare(x, y Member) int {
	return cmp.Or(
		cmp.Compare(x.CWEID, y.CWEID),
		cmp.Compare(x.ViewID, y.ViewID),
	)
}
