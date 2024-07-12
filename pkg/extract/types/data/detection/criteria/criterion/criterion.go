package criterion

import (
	"cmp"

	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
)

type Criterion struct {
	Vulnerable bool                    `json:"vulnerable,omitempty"`
	Package    packageTypes.Package    `json:"package,omitempty"`
	Affected   *affectedTypes.Affected `json:"affected,omitempty"`
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
