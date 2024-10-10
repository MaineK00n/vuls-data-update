package advisory

import (
	"cmp"
	"slices"

	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	scopeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/scope"
)

type Advisory struct {
	Content contentTypes.Content `json:"content,omitempty"`
	Scopes  []scopeTypes.Scope   `json:"scopes,omitempty"`
}

func (a *Advisory) Sort() {
	a.Content.Sort()

	slices.SortFunc(a.Scopes, scopeTypes.Compare)
}

func Compare(x, y Advisory) int {
	return cmp.Or(
		contentTypes.Compare(x.Content, y.Content),

		slices.CompareFunc(x.Scopes, y.Scopes, scopeTypes.Compare),
	)
}
