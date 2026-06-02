package relatedweakness

import "cmp"

type RelatedWeakness struct {
	Nature  string `json:"nature,omitempty"`
	CWEID   string `json:"cweid,omitempty"`
	ViewID  string `json:"view_id,omitempty"`
	Ordinal string `json:"ordinal,omitempty"`  // "Primary" | "Resultant"
	ChainID string `json:"chain_id,omitempty"` // Chain relationship member ID
}

func Compare(x, y RelatedWeakness) int {
	return cmp.Or(
		cmp.Compare(x.Nature, y.Nature),
		cmp.Compare(x.CWEID, y.CWEID),
		cmp.Compare(x.ViewID, y.ViewID),
		cmp.Compare(x.Ordinal, y.Ordinal),
		cmp.Compare(x.ChainID, y.ChainID),
	)
}
