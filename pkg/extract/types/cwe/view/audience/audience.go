package audience

import "cmp"

type Audience struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y Audience) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Description, y.Description),
	)
}
