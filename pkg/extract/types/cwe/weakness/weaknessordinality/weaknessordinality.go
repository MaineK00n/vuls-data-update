package weaknessordinality

import "cmp"

type WeaknessOrdinality struct {
	Ordinality  string `json:"ordinality,omitempty"` // "Primary" | "Resultant" | "Indirect"
	Description string `json:"description,omitempty"`
}

func Compare(x, y WeaknessOrdinality) int {
	return cmp.Or(
		cmp.Compare(x.Ordinality, y.Ordinality),
		cmp.Compare(x.Description, y.Description),
	)
}
