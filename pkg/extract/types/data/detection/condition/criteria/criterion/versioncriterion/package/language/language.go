package language

import (
	"cmp"
	"slices"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Functions     []string `json:"functions,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
	slices.Sort(p.Functions)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Architectures, y.Architectures),
		slices.Compare(x.Functions, y.Functions),
	)
}

type Query struct {
	Name      string
	Arch      string
	Functions []string
}

func (p Package) Accept(query Query) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if query.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Arch) {
		return false, nil
	}

	if len(query.Functions) > 0 && len(p.Functions) > 0 && !slices.ContainsFunc(p.Functions, func(e string) bool {
		return slices.Contains(query.Functions, e)
	}) {
		return false, nil
	}

	return true, nil
}
