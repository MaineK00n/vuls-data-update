package criterionpackage

import (
	"cmp"
	"slices"

	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
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

type Query struct {
	Package *QueryPackage
	CPE     *string
}

type QueryPackage struct {
	Name       string
	Arch       string
	Repository string
	Functions  []string
}

func (p Package) Accept(query Query) (bool, error) {
	switch {
	case query.Package != nil:
		if query.Package.Name != p.Name {
			return false, nil
		}

		if query.Package.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Package.Arch) {
			return false, nil
		}

		if query.Package.Repository != "" && len(p.Repositories) > 0 && !slices.Contains(p.Repositories, query.Package.Repository) {
			return false, nil
		}

		if len(query.Package.Functions) > 0 && len(p.Functions) > 0 && !slices.ContainsFunc(p.Functions, func(e string) bool {
			return slices.Contains(query.Package.Functions, e)
		}) {
			return false, nil
		}

		return true, nil
	case query.CPE != nil:
		wfn1, err := naming.UnbindFS(*query.CPE)
		if err != nil {
			return false, errors.Wrapf(err, "unbind %q to WFN", *query.CPE)
		}

		wfn2, err := naming.UnbindFS(p.CPE)
		if err != nil {
			return false, nil
		}

		return matching.IsSubset(wfn1, wfn2), nil
	default:
		return false, errors.Errorf("query must be set to Package or CPE")
	}
}
