package remediation

import "cmp"

type Remediation struct {
	Source      string `json:"source,omitempty"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y Remediation) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		cmp.Compare(x.Description, y.Description),
	)
}
