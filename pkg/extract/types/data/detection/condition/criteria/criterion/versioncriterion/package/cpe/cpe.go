package cpe

import (
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
)

type CPE string

type Query string

func (p CPE) Accept(query Query) (bool, error) {
	queryWFN, err := naming.UnbindFS(string(query))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(query))
	}

	patternWFN, err := naming.UnbindFS(string(p))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(p))
	}

	return !matching.IsDisjoint(queryWFN, patternWFN), nil
}
