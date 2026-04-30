package cpe

import (
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
)

type CPE string

type Query string

func (c CPE) Accept(query Query) (bool, error) {
	qWFN, err := naming.UnbindFS(string(query))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(query))
	}

	cWFN, err := naming.UnbindFS(string(c))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(c))
	}

	return !matching.IsDisjoint(qWFN, cWFN), nil
}
