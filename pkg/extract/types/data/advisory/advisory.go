package advisory

import (
	"cmp"
	"slices"

	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
)

type Advisory struct {
	Content     contentTypes.Content        `json:"content,omitempty"`
	Ecosystems  []ecosystemTypes.Ecosystem  `json:"ecosystems,omitempty"`
	Ecosystems2 []ecosystemTypes.Ecosystem2 `json:"ecosystems2,omitempty"`
}

func (a *Advisory) Sort() {
	a.Content.Sort()

	slices.Sort(a.Ecosystems)
}

func Compare(x, y Advisory) int {
	return cmp.Or(
		contentTypes.Compare(x.Content, y.Content),
		slices.Compare(x.Ecosystems, y.Ecosystems),
	)
}
