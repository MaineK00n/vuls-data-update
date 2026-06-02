package reason

import "cmp"

type Reason struct {
	Type string `json:"type,omitempty"`
}

func Compare(x, y Reason) int {
	return cmp.Compare(x.Type, y.Type)
}
