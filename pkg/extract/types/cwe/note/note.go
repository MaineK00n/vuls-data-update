package note

import "cmp"

type Note struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
}

func Compare(x, y Note) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Text, y.Text),
	)
}
