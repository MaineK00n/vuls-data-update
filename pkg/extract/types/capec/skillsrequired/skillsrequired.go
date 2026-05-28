package skillsrequired

import "cmp"

type SkillsRequired struct {
	High   string `json:"high,omitempty"`
	Medium string `json:"medium,omitempty"`
	Low    string `json:"low,omitempty"`
}

func Compare(x, y SkillsRequired) int {
	return cmp.Or(
		cmp.Compare(x.High, y.High),
		cmp.Compare(x.Medium, y.Medium),
		cmp.Compare(x.Low, y.Low),
	)
}
