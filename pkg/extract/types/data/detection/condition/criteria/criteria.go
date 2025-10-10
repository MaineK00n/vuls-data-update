package criteria

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/pkg/errors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
)

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

type Criteria struct {
	Operator   CriteriaOperatorType       `json:"operator,omitempty"`
	Criterias  []Criteria                 `json:"criterias,omitempty"`
	Criterions []criterionTypes.Criterion `json:"criterions,omitempty"`
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

func (c Criteria) Contains(query criterionTypes.Query) (bool, error) {
	for _, ca := range c.Criterias {
		isContained, err := ca.Contains(query)
		if err != nil {
			return false, errors.Wrap(err, "criteria contains")
		}
		if isContained {
			return true, nil
		}
	}

	for _, cn := range c.Criterions {
		isContained, err := cn.Contains(query)
		if err != nil {
			return false, errors.Wrap(err, "criterion accept")
		}
		if isContained {
			return true, nil
		}
	}
	return false, nil
}

type FilteredCriteria struct {
	Operator   CriteriaOperatorType               `json:"operator,omitempty"`
	Criterias  []FilteredCriteria                 `json:"criterias,omitempty"`
	Criterions []criterionTypes.FilteredCriterion `json:"criterions,omitempty"`
}

func (c Criteria) Accept(query criterionTypes.Query) (FilteredCriteria, error) {
	filtered := FilteredCriteria{
		Operator: c.Operator,
		Criterias: func() []FilteredCriteria {
			if len(c.Criterias) > 0 {
				return make([]FilteredCriteria, 0, len(c.Criterias))
			}
			return nil
		}(),
		Criterions: func() []criterionTypes.FilteredCriterion {
			if len(c.Criterions) > 0 {
				return make([]criterionTypes.FilteredCriterion, 0, len(c.Criterions))
			}
			return nil
		}(),
	}

	for _, ca := range c.Criterias {
		fca, err := ca.Accept(query)
		if err != nil {
			return FilteredCriteria{}, errors.Wrap(err, "criteria accept")
		}
		filtered.Criterias = append(filtered.Criterias, fca)
	}

	for _, cn := range c.Criterions {
		fcn, err := cn.Accept(query)
		if err != nil {
			return FilteredCriteria{}, errors.Wrap(err, "criterion accept")
		}
		filtered.Criterions = append(filtered.Criterions, fcn)
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
			isAffected, err := cn.Affected()
			if err != nil {
				return false, errors.Wrap(err, "criterion affected")
			}
			if !isAffected {
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
			isAffected, err := cn.Affected()
			if err != nil {
				return false, errors.Wrap(err, "criterion affected")
			}
			if isAffected {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected criteria operator type. expected: %q, actual: %q", []CriteriaOperatorType{CriteriaOperatorTypeAND, CriteriaOperatorTypeOR}, c.Operator)
	}
}
