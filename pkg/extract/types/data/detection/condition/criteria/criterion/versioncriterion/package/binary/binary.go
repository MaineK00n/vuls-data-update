package binary

import (
	"cmp"
	"slices"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	// SrcName is the source package the binary was built from, for feeds that
	// record it. Two source packages can build binaries of the same name in
	// one product with different fix states (e.g. kernel and kernel-alt both
	// build kernel in RHEL 7 ELS), which the name alone cannot tell apart.
	// Empty means the feed does not say, and Accept then ignores it.
	SrcName string `json:"src_name,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Architectures, y.Architectures),
		cmp.Compare(x.SrcName, y.SrcName),
	)
}

type Query struct {
	Name         string
	Arch         string
	SrcName      string
	Repositories []string
}

func (p Package) Accept(query Query, repositories []string) (bool, error) {
	if query.Name != p.Name {
		return false, nil
	}

	if query.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Arch) {
		return false, nil
	}

	// Narrow by source package only when both sides name one. Most feeds do
	// not record it, and a caller that cannot determine the source package of
	// an installed binary leaves the query empty — either way the criterion
	// must stay matchable, so an absent value means "any" rather than "none".
	if query.SrcName != "" && p.SrcName != "" && query.SrcName != p.SrcName {
		return false, nil
	}

	if len(query.Repositories) > 0 && len(repositories) > 0 && !slices.ContainsFunc(query.Repositories, func(r string) bool {
		return slices.Contains(repositories, r)
	}) {
		return false, nil
	}

	return true, nil
}
