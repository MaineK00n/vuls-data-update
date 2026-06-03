package mitigation

import "cmp"

// Mitigation captures a CAPEC mitigation extracted from a STIX
// course-of-action object that is linked to the attack-pattern via a
// relationship of type "mitigates".
type Mitigation struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y Mitigation) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Description, y.Description),
	)
}
