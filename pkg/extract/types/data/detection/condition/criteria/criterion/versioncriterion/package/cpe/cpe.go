package cpe

import (
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
)

type CPE string

type Query string

func (p CPE) Accept(query Query) (bool, error) {
	wfn1, err := naming.UnbindFS(string(query))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(query))
	}

	wfn2, err := naming.UnbindFS(string(p))
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", string(p))
	}

	return matching.IsSubset(wfn1, wfn2), nil
}
