package noneexistcriterion

import (
	"cmp"
	"slices"
)

type Criterion struct {
	Name string `json:"name,omitempty"`
	Arch string `json:"arch,omitempty"`
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Arch, y.Arch),
	)
}

type Query struct {
	Binaries []string `json:"binaries,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

func (c Criterion) Accept(query Query) (bool, error) {
	switch c.Arch {
	case "src":
		return !slices.Contains(query.Sources, c.Name), nil
	default:
		return !slices.Contains(query.Binaries, c.Name), nil
	}
}
