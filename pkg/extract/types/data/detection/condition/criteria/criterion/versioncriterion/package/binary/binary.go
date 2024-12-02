package binary

import (
	"cmp"
	"slices"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Repositories  []string `json:"repositories,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
	slices.Sort(p.Repositories)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Architectures, y.Architectures),
		slices.Compare(x.Repositories, y.Repositories),
	)
}

type Query struct {
	Name       string
	Arch       string
	Repository string
}

func (p Package) Accept(query Query) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if query.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Arch) {
		return false, nil
	}

	if query.Repository != "" && len(p.Repositories) > 0 && !slices.Contains(p.Repositories, query.Repository) {
		return false, nil
	}

	return true, nil
}
