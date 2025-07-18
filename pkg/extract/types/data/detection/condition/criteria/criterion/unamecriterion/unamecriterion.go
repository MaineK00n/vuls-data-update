package unamecriterion

import (
	"cmp"
	"regexp"

	"github.com/pkg/errors"
)

// FIXME: add other fields
type Criterion struct {
	Release *string `json:"release,omitempty"`
}

func (c *Criterion) Sort() {
}

func Compare(x, y Criterion) int {
	switch {
	case x.Release == nil && y.Release == nil:
		return 0
	case x.Release == nil && y.Release != nil:
		return -1
	case x.Release != nil && y.Release == nil:
		return +1
	default:
		return cmp.Compare(*x.Release, *y.Release)
	}
}

type Query struct {
	Release *string
}

// FIXME: write unit tests
func (c Criterion) Accept(query Query) (bool, error) {
	if query.Release == nil {
		return false, nil
	}
	if c.Release == nil {
		return true, nil
	}

	r, err := regexp.Compile(*c.Release)
	if err != nil {
		return false, errors.Wrapf(err, "compile %q", *c.Release)
	}

	return r.Match([]byte(*query.Release)), nil
}
