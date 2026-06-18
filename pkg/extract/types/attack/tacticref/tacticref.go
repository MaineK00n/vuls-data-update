package tacticref

import "cmp"

// TacticRef pairs a Tactic's kill-chain shortname (e.g.,
// "credential-access") with its ATT&CK external ID (e.g., "TA0006").
// Used wherever a Technique lists the Tactics it belongs to, so
// downstream consumers can resolve both the URL slug (shortname) and
// the full Tactic record (via ID) without a second lookup pass.
type TacticRef struct {
	Shortname string `json:"shortname"`
	ID        string `json:"id,omitempty"`
}

func Compare(x, y TacticRef) int {
	return cmp.Or(
		cmp.Compare(x.Shortname, y.Shortname),
		cmp.Compare(x.ID, y.ID),
	)
}
