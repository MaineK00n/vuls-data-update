package suggestion

import "cmp"

type Suggestion struct {
	CWEID   string `json:"cweid,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func Compare(x, y Suggestion) int {
	return cmp.Or(
		cmp.Compare(x.CWEID, y.CWEID),
		cmp.Compare(x.Comment, y.Comment),
	)
}
