package reference

import (
	"cmp"
	"slices"
)

type Reference struct {
	Name   string   `json:"name,omitempty"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url,omitempty"`
}

func (r *Reference) Sort() {
	slices.Sort(r.Tags)
}

func Compare(x, y Reference) int {
	if c := cmp.Compare(x.Source, y.Source); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Name, y.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(x.URL, y.URL); c != 0 {
		return c
	}
	return slices.Compare(x.Tags, y.Tags)
}
