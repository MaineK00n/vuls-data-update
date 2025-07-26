package source

import (
	"cmp"
	"slices"
)

type Package struct {
	Name         string   `json:"name,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Repositories)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Repositories, y.Repositories),
	)
}

type Query struct {
	Name       string
	Repository string
}

func (p Package) Accept(query Query) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if query.Repository != "" && len(p.Repositories) > 0 && !slices.Contains(p.Repositories, query.Repository) {
		return false, nil
	}

	return true, nil
}
