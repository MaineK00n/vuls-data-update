package binary

import (
	"cmp"
	"slices"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Architectures, y.Architectures),
	)
}

type Query struct {
	Name       string
	Arch       string
	Repository string
}

func (p Package) Accept(query Query, repositories []string) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if query.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Arch) {
		return false, nil
	}

	if query.Repository != "" && len(repositories) > 0 && !slices.Contains(repositories, query.Repository) {
		return false, nil
	}

	return true, nil
}
