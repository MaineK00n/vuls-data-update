package reference

import (
	"cmp"
	"slices"
)

type Reference struct {
	Source string   `json:"source,omitempty"`
	URL    string   `json:"url,omitempty"`
	Title  string   `json:"title,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

func (r *Reference) Sort() {
	slices.Sort(r.Tags)
}

func Compare(x, y Reference) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		cmp.Compare(x.URL, y.URL),
		cmp.Compare(x.Title, y.Title),
		slices.CompareFunc(x.Tags, y.Tags, cmp.Compare),
	)
}
