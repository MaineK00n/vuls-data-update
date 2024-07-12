package criterionpackage

import (
	"cmp"
	"slices"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	CPE           string   `json:"cpe,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Repositories  []string `json:"repositories,omitempty"`
	Functions     []string `json:"functions,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
	slices.Sort(p.Repositories)
	slices.Sort(p.Functions)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.CPE, y.CPE),
		slices.Compare(x.Architectures, y.Architectures),
		slices.Compare(x.Repositories, y.Repositories),
		slices.Compare(x.Functions, y.Functions),
	)
}
