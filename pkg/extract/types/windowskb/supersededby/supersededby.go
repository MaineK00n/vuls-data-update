package supersededby

import "cmp"

// SupersededBy represents a reference to a superseding update.
type SupersededBy struct {
	KBID     string `json:"kb_id,omitempty"`
	UpdateID string `json:"update_id,omitempty"`
}

func (d *SupersededBy) Sort() {}

func Compare(x, y SupersededBy) int {
	return cmp.Or(
		cmp.Compare(x.KBID, y.KBID),
		cmp.Compare(x.UpdateID, y.UpdateID),
	)
}
