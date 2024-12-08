package versoncriterion

import (
	"cmp"
	"slices"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Criterion struct {
	Vulnerable bool                      `json:"vulnerable,omitempty"`
	FixStatus  *fixstatusTypes.FixStatus `json:"fix_status,omitempty"`
	Package    packageTypes.Package      `json:"package,omitempty"`
	Affected   *affectedTypes.Affected   `json:"affected,omitempty"`
}

func (c *Criterion) Sort() {
	(&c.Package).Sort()
	if c.Affected != nil {
		c.Affected.Sort()
	}
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		func() int {
			switch {
			case !x.Vulnerable && y.Vulnerable:
				return -1
			case x.Vulnerable && !y.Vulnerable:
				return +1
			default:
				return 0
			}
		}(),
		func() int {
			switch {
			case x.FixStatus == nil && y.FixStatus == nil:
				return 0
			case x.FixStatus == nil && y.FixStatus != nil:
				return -1
			case x.FixStatus != nil && y.FixStatus == nil:
				return +1
			default:
				return fixstatusTypes.Compare(*x.FixStatus, *y.FixStatus)
			}
		}(),
		packageTypes.Compare(x.Package, y.Package),
		func() int {
			switch {
			case x.Affected == nil && y.Affected == nil:
				return 0
			case x.Affected == nil && y.Affected != nil:
				return -1
			case x.Affected != nil && y.Affected == nil:
				return +1
			default:
				return affectedTypes.Compare(*x.Affected, *y.Affected)
			}
		}(),
	)
}

type Query struct {
	Family  string
	Package *QueryPackage
	CPE     *string
}

type QueryPackage struct {
	Name       string
	Version    string
	SrcName    string
	SrcVersion string
	Arch       string
	Repository string
	Functions  []string
}

func (c Criterion) Accept(query Query) (bool, error) {
	switch query.Family {
	case ecosystemTypes.EcosystemTypeCPE:
		if query.CPE == nil {
			return false, errors.New("query is not set for CPE criterion")
		}

		isAccepted, err := c.Package.Accept(packageTypes.Query{CPE: query.CPE})
		if err != nil {
			return false, errors.Wrap(err, "package accept")
		}

		if !isAccepted {
			return false, nil
		}

		wfn1, err := naming.UnbindFS(c.Package.CPE)
		if err != nil {
			return false, errors.Wrapf(err, "unbind %q to WFN", c.Package.CPE)
		}

		switch wfn1.GetString(common.AttributeVersion) {
		case "ANY":
			if c.Affected == nil {
				return true, nil
			}

			wfn2, err := naming.UnbindFS(*query.CPE)
			if err != nil {
				return false, errors.Wrapf(err, "unbind %q to WFN", *query.CPE)
			}

			isAccepted, err := c.Affected.Accept(query.Family, strings.ReplaceAll(wfn2.GetString(common.AttributeVersion), "\\.", "."))
			if err != nil {
				return false, errors.Wrap(err, "affected accpet")
			}

			return isAccepted, nil
		case "NA":
			return true, nil
		default:
			return true, nil
		}
	default:
		if query.Package == nil {
			return false, errors.New("query is not set for Package criterion")
		}

		name, version, arch := query.Package.Name, query.Package.Version, query.Package.Arch
		if slices.Contains(c.Package.Architectures, "src") {
			name, version, arch = query.Package.SrcName, query.Package.SrcVersion, "src"
		}

		isAccepted, err := c.Package.Accept(packageTypes.Query{Package: &packageTypes.QueryPackage{
			Name:       name,
			Arch:       arch,
			Repository: query.Package.Repository,
			Functions:  query.Package.Functions,
		}})
		if err != nil {
			return false, errors.Wrap(err, "package accept")
		}

		if !isAccepted {
			return false, nil
		}

		if c.Affected == nil {
			return true, nil
		}

		isAccepted, err = c.Affected.Accept(query.Family, version)
		if err != nil {
			return false, errors.Wrap(err, "affected accept")
		}

		return isAccepted, nil
	}
}
