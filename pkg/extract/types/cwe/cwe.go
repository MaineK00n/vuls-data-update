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
	if c := cmp.Compare(x.Source, y.Source); c != 0 {
		return c
	}
	return slices.Compare(x.CWE, y.CWE)
}
