package criteria

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/pkg/errors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
)

type Criteria struct {
	Operator   CriteriaOperatorType       `json:"operator,omitempty"`
	Criterias  []Criteria                 `json:"criterias,omitempty"`
	Criterions []criterionTypes.Criterion `json:"criterions,omitempty"`
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
	slices.SortFunc(c.Criterions, criterionTypes.Compare)

	for i := range c.Criterias {
		(&c.Criterias[i]).Sort()
	}
	slices.SortFunc(c.Criterias, Compare)
}

func Compare(x, y Criteria) int {
	return cmp.Or(
		cmp.Compare(x.Operator, y.Operator),
		slices.CompareFunc(x.Criterions, y.Criterions, criterionTypes.Compare),
		slices.CompareFunc(x.Criterias, y.Criterias, Compare),
	)
}

type FilteredCriteria struct {
	Operator   CriteriaOperatorType `json:"operator,omitempty"`
	Criterias  []FilteredCriteria   `json:"criterias,omitempty"`
	Criterions []FilteredCriterion  `json:"criterions,omitempty"`
}

type FilteredCriterion struct {
	Criterion criterionTypes.Criterion
	Accepts   []int
}

func (c Criteria) Contains(ecosystem ecosystemTypes.Ecosystem, query criterionTypes.Query) (bool, error) {
	for _, ca := range c.Criterias {
		isAccepted, err := ca.Contains(ecosystem, query)
		if err != nil {
			return false, errors.Wrap(err, "criteria contains")
		}
		if isAccepted {
			return true, nil
		}
	}

	for _, cn := range c.Criterions {
		isAccepted, err := cn.Accept(ecosystem, query)
		if err != nil {
			return false, errors.Wrap(err, "criterion accept")
		}
		if isAccepted {
			return true, nil
		}
	}
	return false, nil
}

func (c Criteria) Accept(ecosystem ecosystemTypes.Ecosystem, queries []criterionTypes.Query) (FilteredCriteria, error) {
	filtered := FilteredCriteria{
		Operator: c.Operator,
		Criterias: func() []FilteredCriteria {
			if len(c.Criterias) > 0 {
				return make([]FilteredCriteria, 0, len(c.Criterias))
			}
			return nil
		}(),
		Criterions: func() []FilteredCriterion {
			if len(c.Criterions) > 0 {
				return make([]FilteredCriterion, 0, len(c.Criterions))
			}
			return nil
		}(),
	}

	for _, ca := range c.Criterias {
		fca, err := ca.Accept(ecosystem, queries)
		if err != nil {
			return FilteredCriteria{}, errors.Wrap(err, "criteria accept")
		}
		filtered.Criterias = append(filtered.Criterias, fca)
	}

	for _, cn := range c.Criterions {
		var is []int
		for i, q := range queries {
			isAccepted, err := cn.Accept(ecosystem, q)
			if err != nil {
				return FilteredCriteria{}, errors.Wrap(err, "criterion accept")
			}
			if isAccepted {
				is = append(is, i)
			}
		}
		filtered.Criterions = append(filtered.Criterions, FilteredCriterion{
			Criterion: cn,
			Accepts:   is,
		})
	}

	return filtered, nil
}

func (c FilteredCriteria) Affected() (bool, error) {
	switch c.Operator {
	case CriteriaOperatorTypeAND:
		for _, ca := range c.Criterias {
			isAffected, err := ca.Affected()
			if err != nil {
				return false, errors.Wrap(err, "criteria affected")
			}
			if !isAffected {
				return false, nil
			}
		}

		for _, cn := range c.Criterions {
			if cn.Criterion.Vulnerable && len(cn.Accepts) == 0 {
				return false, nil
			}
		}
		return true, nil
	case CriteriaOperatorTypeOR:
		for _, ca := range c.Criterias {
			isAffected, err := ca.Affected()
			if err != nil {
				return false, errors.Wrap(err, "criteria affected")
			}
			if isAffected {
				return true, nil
			}
		}

		for _, cn := range c.Criterions {
			if cn.Criterion.Vulnerable && len(cn.Accepts) > 0 {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected criteria operator type. expected: %q, actual: %q", []CriteriaOperatorType{CriteriaOperatorTypeAND, CriteriaOperatorTypeOR}, c.Operator)
	}
}
