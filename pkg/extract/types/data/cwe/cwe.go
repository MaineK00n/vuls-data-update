package cwe

import (
	"cmp"
	"slices"
)

type CWE struct {
	Source string   `json:"source,omitempty"`
	CWE    []string `json:"cwe,omitempty"`
}

func (c *CWE) Sort() {
	slices.Sort(c.CWE)
}

func Compare(x, y CWE) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		slices.Compare(x.CWE, y.CWE),
	)
}
