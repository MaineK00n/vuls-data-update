package supersedes

import "cmp"

// Supersedes represents a reference to a superseded (older) update.
type Supersedes struct {
	KBID     string `json:"kb_id,omitempty"`
	UpdateID string `json:"update_id,omitempty"`
}

func Compare(x, y Supersedes) int {
	return cmp.Or(
		cmp.Compare(x.KBID, y.KBID),
		cmp.Compare(x.UpdateID, y.UpdateID),
	)
}
