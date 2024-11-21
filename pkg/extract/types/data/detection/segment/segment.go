package segment

import (
	"cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type DetectionTag string

type Segment struct {
	Ecosystem ecosystem.Ecosystem `json:"ecosystem,omitempty"`
	Tag       DetectionTag        `json:"tag,omitempty"`
}

func Compare(x, y Segment) int {
	return cmp.Or(
		cmp.Compare(x.Ecosystem, y.Ecosystem),
		cmp.Compare(x.Tag, y.Tag),
	)
}
