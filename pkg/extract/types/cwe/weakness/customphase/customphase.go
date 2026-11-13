package customphase

import "cmp"

// CustomPhase is a lifecycle phase of a domain that has a lifecycle of its own
// (CWE 5.0), e.g. Domain "AI" with Phase "Training".
type CustomPhase struct {
	Domain string `json:"domain,omitempty"`
	Phase  string `json:"phase,omitempty"`
}

func Compare(x, y CustomPhase) int {
	return cmp.Or(
		cmp.Compare(x.Domain, y.Domain),
		cmp.Compare(x.Phase, y.Phase),
	)
}
