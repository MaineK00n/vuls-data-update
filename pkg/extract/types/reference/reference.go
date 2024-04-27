package reference

import "cmp"

type Reference struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}

func Compare(x, y Reference) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		cmp.Compare(x.URL, y.URL),
	)
}
