package repository

import "cmp"

type Repository struct {
	URL    string `json:"url,omitempty"`
	Commit string `json:"commit,omitempty"`
}

func Compare(x, y Repository) int {
	return cmp.Or(
		cmp.Compare(x.URL, y.URL),
		cmp.Compare(x.Commit, y.Commit),
	)
}
