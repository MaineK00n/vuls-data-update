package advisory

import (
	"cmp"
	"slices"

	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
)

type Advisory struct {
	Content    contentTypes.Content       `json:"content,omitempty"`
	Ecosystems []ecosystemTypes.Ecosystem `json:"ecosystems,omitempty"`
}

func (a *Advisory) Sort() {
	a.Content.Sort()

	slices.SortFunc(a.Ecosystems, ecosystemTypes.Compare)
}

func Compare(x, y Advisory) int {
	return cmp.Or(
		contentTypes.Compare(x.Content, y.Content),

		slices.CompareFunc(x.Ecosystems, y.Ecosystems, ecosystemTypes.Compare),
	)
}
