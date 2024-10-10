package scope

import (
	"cmp"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/scope/ecosystem"
)

type Scope struct {
	Ecosystem ecosystemTypes.Ecosystem `json:"ecosystem,omitempty"`
	Channel   string                   `json:"channel,omitempty"`
}

func Compare(x, y Scope) int {
	return cmp.Or(
		cmp.Compare(x.Ecosystem, y.Ecosystem),
		cmp.Compare(x.Channel, y.Channel),
	)
}
