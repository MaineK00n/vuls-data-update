package source

import (
	"cmp"
	"slices"
)

type Package struct {
	Name string `json:"name,omitempty"`
}

func (p *Package) Sort() {
}

func Compare(x, y Package) int {
	return cmp.Compare(x.Name, y.Name)
}

type Query struct {
	Name         string
	Repositories []string
}

func (p Package) Accept(query Query, repositories []string) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if len(query.Repositories) > 0 && len(repositories) > 0 && !slices.ContainsFunc(query.Repositories, func(r string) bool {
		return slices.Contains(repositories, r)
	}) {
		return false, nil
	}

	return true, nil
}
