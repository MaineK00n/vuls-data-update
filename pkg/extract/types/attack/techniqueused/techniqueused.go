package techniqueused

import "cmp"

type TechniqueUsed struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
}

func Compare(x, y TechniqueUsed) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Description, y.Description),
	)
}
