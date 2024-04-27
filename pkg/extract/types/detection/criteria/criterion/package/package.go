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
	if c := cmp.Compare(x.Name, y.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(x.CPE, y.CPE); c != 0 {
		return c
	}
	if c := slices.Compare(x.Architectures, y.Architectures); c != 0 {
		return c
	}
	if c := slices.Compare(x.Repositories, y.Repositories); c != 0 {
		return c
	}
	return slices.Compare(x.Functions, y.Functions)
}
