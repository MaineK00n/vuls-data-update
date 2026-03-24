package kbcriterion

import (
	"cmp"
	"slices"
)

type Criterion struct {
	Product string `json:"product,omitempty"`
	KBID    string `json:"kb_id,omitempty"`
}

func (c *Criterion) Sort() {}

func Compare(x, y Criterion) int {
	return cmp.Or(
		cmp.Compare(x.Product, y.Product),
		cmp.Compare(x.KBID, y.KBID),
	)
}

type Query struct {
	UnappliedKBs []string
}

func (c Criterion) Accept(query Query) (bool, error) {
	return slices.Contains(query.UnappliedKBs, c.KBID), nil
}
