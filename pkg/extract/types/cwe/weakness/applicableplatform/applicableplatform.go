package applicableplatform

import (
	"cmp"
)

type ApplicablePlatform struct {
	Type       string `json:"type"` // "language" | "technology" | "os" | "architecture"
	Name       string `json:"name,omitempty"`
	Class      string `json:"class,omitempty"`
	Prevalence string `json:"prevalence,omitempty"`
	Note       string `json:"note,omitempty"` // CWE 5.0
}

func Compare(x, y ApplicablePlatform) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Class, y.Class),
		cmp.Compare(x.Prevalence, y.Prevalence),
		cmp.Compare(x.Note, y.Note),
	)
}
