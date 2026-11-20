package dimension

import "cmp"

// Dimension identifies what a CWE entry, or one of its relationships, is
// based on (CWE 5.0), e.g. Type "Behavior-Type" with Value "Timing".
type Dimension struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func Compare(x, y Dimension) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Value, y.Value),
	)
}
