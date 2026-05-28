package procedure

import "cmp"

type Procedure struct {
	AttackerID  string `json:"attacker_id"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y Procedure) int {
	return cmp.Or(
		cmp.Compare(x.AttackerID, y.AttackerID),
		cmp.Compare(x.Description, y.Description),
	)
}
