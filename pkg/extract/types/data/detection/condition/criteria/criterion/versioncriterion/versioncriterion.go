package versioncriterion

import (
	"cmp"

	"github.com/pkg/errors"

	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Criterion struct {
	Vulnerable bool                      `json:"vulnerable,omitempty"`
	FixStatus  *fixstatusTypes.FixStatus `json:"fix_status,omitempty"`
	Package    packageTypes.Package      `json:"package,omitzero"`
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
	Binary   *QueryBinary
	Source   *QuerySource
	Language *QueryLanguage
}

type QueryBinary struct {
	Family       ecosystemTypes.Ecosystem
	Name         string
	Version      string
	Arch         string
	Repositories []string
}

type QuerySource struct {
	Family       ecosystemTypes.Ecosystem
	Name         string
	Version      string
	Repositories []string
}

type QueryLanguage struct {
	Ecosystem ecosystemTypes.Ecosystem
	Name      string
	Version   string
	Arch      string
	Functions []string
}

func (c Criterion) Accept(query Query, repositories []string) (bool, error) {
	switch c.Package.Type {
	case packageTypes.PackageTypeBinary:
		if query.Binary == nil {
			return false, nil
		}
		isAccepted, err := c.Package.Accept(packageTypes.Query{
			Binary: &binaryTypes.Query{
				Name:         query.Binary.Name,
				Arch:         query.Binary.Arch,
				Repositories: query.Binary.Repositories,
			},
		}, repositories)
		if err != nil {
			return false, errors.Wrap(err, "package accept")
		}
		if !isAccepted {
			return false, nil
		}

		if c.Affected == nil {
			return true, nil
		}
		isAccepted, err = c.Affected.Accept(query.Binary.Family, query.Binary.Version)
		if err != nil {
			return false, errors.Wrap(err, "affected accept")
		}
		return isAccepted, nil
	case packageTypes.PackageTypeSource:
		if query.Source == nil {
			return false, nil
		}
		isAccepted, err := c.Package.Accept(packageTypes.Query{
			Source: &sourceTypes.Query{
				Name:         query.Source.Name,
				Repositories: query.Source.Repositories,
			},
		}, repositories)
		if err != nil {
			return false, errors.Wrap(err, "package accept")
		}
		if !isAccepted {
			return false, nil
		}

		if c.Affected == nil {
			return true, nil
		}
		isAccepted, err = c.Affected.Accept(query.Source.Family, query.Source.Version)
		if err != nil {
			return false, errors.Wrap(err, "affected accept")
		}
		return isAccepted, nil
	case packageTypes.PackageTypeLanguage:
		if query.Language == nil {
			return false, nil
		}
		isAccepted, err := c.Package.Accept(packageTypes.Query{
			Language: &languageTypes.Query{
				Name:      query.Language.Name,
				Arch:      query.Language.Arch,
				Functions: query.Language.Functions,
			},
		}, nil)
		if err != nil {
			return false, errors.Wrap(err, "package accept")
		}
		if !isAccepted {
			return false, nil
		}

		if c.Affected == nil {
			return true, nil
		}
		isAccepted, err = c.Affected.Accept(query.Language.Ecosystem, query.Language.Version)
		if err != nil {
			return false, errors.Wrap(err, "affected accept")
		}
		return isAccepted, nil
	default:
		return false, errors.Errorf("unexpected version criterion package type. expected: %q, actual: %q", []packageTypes.PackageType{packageTypes.PackageTypeBinary, packageTypes.PackageTypeSource, packageTypes.PackageTypeLanguage}, c.Package.Type)
	}
}
