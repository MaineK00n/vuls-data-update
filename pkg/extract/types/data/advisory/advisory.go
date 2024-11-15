package advisory

import (
	"cmp"
	"slices"

	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
)

type Advisory struct {
	Content  contentTypes.Content   `json:"content,omitempty"`
	Segments []segmentTypes.Segment `json:"segments,omitempty"`
}

func (a *Advisory) Sort() {
	a.Content.Sort()
	slices.SortFunc(a.Segments, segmentTypes.Compare)
}

func Compare(x, y Advisory) int {
	return cmp.Or(
		contentTypes.Compare(x.Content, y.Content),
		slices.CompareFunc(x.Segments, y.Segments, segmentTypes.Compare),
	)
}
