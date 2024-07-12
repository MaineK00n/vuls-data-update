package criteria

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
)

type Criteria struct {
	Operator   CriteriaOperatorType  `json:"operator,omitempty"`
	Criterias  []Criteria            `json:"criterias,omitempty"`
	Criterions []criterion.Criterion `json:"criterions,omitempty"`
}

type CriteriaOperatorType int

const (
	_ CriteriaOperatorType = iota
	CriteriaOperatorTypeOR
	CriteriaOperatorTypeAND
)

func (t CriteriaOperatorType) String() string {
	switch t {
	case CriteriaOperatorTypeOR:
		return "OR"
	case CriteriaOperatorTypeAND:
		return "AND"
	default:
		return ""
	}
}

func (t CriteriaOperatorType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *CriteriaOperatorType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var ct CriteriaOperatorType
	switch s {
	case "OR":
		ct = CriteriaOperatorTypeOR
	case "AND":
		ct = CriteriaOperatorTypeAND
	default:
		return fmt.Errorf("invalid CriteriaOperatorType %s", s)
	}
	*t = ct
	return nil
}

func (c *Criteria) Sort() {
	for i := range c.Criterions {
		(&c.Criterions[i]).Sort()
	}
	slices.SortFunc(c.Criterions, criterion.Compare)

	for i := range c.Criterias {
		(&c.Criterias[i]).Sort()
	}
	slices.SortFunc(c.Criterias, Compare)
}

func Compare(x, y Criteria) int {
	return cmp.Or(
		cmp.Compare(x.Operator, y.Operator),
		slices.CompareFunc(x.Criterions, y.Criterions, criterion.Compare),
		slices.CompareFunc(x.Criterias, y.Criterias, Compare),
	)
}
