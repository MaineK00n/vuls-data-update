package criterion

import (
	"cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/affected"
	criterionpackage "github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/package"
)

type Criterion struct {
	Vulnerable bool                     `json:"vulnerable,omitempty"`
	Package    criterionpackage.Package `json:"package,omitempty"`
	Affected   *affected.Affected       `json:"affected,omitempty"`
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
		criterionpackage.Compare(x.Package, y.Package),
		func() int {
			switch {
			case x.Affected == nil && y.Affected == nil:
				return 0
			case x.Affected == nil && y.Affected != nil:
				return -1
			case x.Affected != nil && y.Affected == nil:
				return +1
			default:
				return affected.Compare(*x.Affected, *y.Affected)
			}
		}(),
	)
}
