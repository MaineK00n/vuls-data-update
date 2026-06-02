package demonstrativeexample

import "cmp"

type DemonstrativeExample struct {
	DemonstrativeExampleID string `json:"demonstrative_example_id,omitempty"`
	Text                   string `json:"text,omitempty"`
}

func Compare(x, y DemonstrativeExample) int {
	return cmp.Or(
		cmp.Compare(x.DemonstrativeExampleID, y.DemonstrativeExampleID),
		cmp.Compare(x.Text, y.Text),
	)
}
