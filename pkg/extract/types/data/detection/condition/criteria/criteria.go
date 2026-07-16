package criteria

import (
	"cmp"
	"slices"

	"github.com/pkg/errors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// CriteriaOperatorType is a string so that unmarshaling never validates
// against the known set: data produced by a newer vuls-data-update (carrying
// operator types this build does not know) still round-trips losslessly
// instead of failing the whole read. Unlike the other enums, evaluation
// (FilteredCriteria.Affected) stays strict on out-of-vocabulary values —
// see the rationale on its default branch.
type CriteriaOperatorType string

const (
	CriteriaOperatorTypeOR  CriteriaOperatorType = "OR"
	CriteriaOperatorTypeAND CriteriaOperatorType = "AND"
)

// CriteriaOperatorTypes returns every CriteriaOperatorType this build knows,
// in declaration order. Consumers (vuls2, vuls0) diff this list against a
// newer vuls-data-update in CI to detect enum additions that require a
// dependency bump. The known set must be append-only.
func CriteriaOperatorTypes() []CriteriaOperatorType {
	return []CriteriaOperatorType{
		CriteriaOperatorTypeOR,
		CriteriaOperatorTypeAND,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// CriteriaOperatorTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t CriteriaOperatorType) Compare(u CriteriaOperatorType) int {
	return enum.Compare(CriteriaOperatorTypes(), t, u)
}

type Criteria struct {
	Operator     CriteriaOperatorType       `json:"operator,omitempty"`
	Criterias    []Criteria                 `json:"criterias,omitempty"`
	Criterions   []criterionTypes.Criterion `json:"criterions,omitempty"`
	Repositories []string                   `json:"repositories,omitempty"`
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

	slices.Sort(c.Repositories)
}

func Compare(x, y Criteria) int {
	return cmp.Or(
		x.Operator.Compare(y.Operator),
		slices.CompareFunc(x.Criterions, y.Criterions, criterionTypes.Compare),
		slices.CompareFunc(x.Criterias, y.Criterias, Compare),
		slices.Compare(x.Repositories, y.Repositories),
	)
}

func (c Criteria) Contains(query criterionTypes.Query, parentRepositories []string) (bool, error) {
	repositories := parentRepositories
	if len(c.Repositories) > 0 {
		repositories = c.Repositories
	}

	for _, ca := range c.Criterias {
		isContained, err := ca.Contains(query, repositories)
		if err != nil {
			return false, errors.Wrap(err, "criteria contains")
		}
		if isContained {
			return true, nil
		}
	}

	for _, cn := range c.Criterions {
		isContained, err := cn.Contains(query, repositories)
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
	Operator     CriteriaOperatorType               `json:"operator,omitempty"`
	Criterias    []FilteredCriteria                 `json:"criterias,omitempty"`
	Criterions   []criterionTypes.FilteredCriterion `json:"criterions,omitempty"`
	Repositories []string                           `json:"repositories,omitempty"`
}

func (c Criteria) Accept(query criterionTypes.Query, parentRepositories []string) (FilteredCriteria, error) {
	repositories := parentRepositories
	if len(c.Repositories) > 0 {
		repositories = c.Repositories
	}

	filtered := FilteredCriteria{
		Operator:     c.Operator,
		Repositories: c.Repositories,
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
		fca, err := ca.Accept(query, repositories)
		if err != nil {
			return FilteredCriteria{}, errors.Wrap(err, "criteria accept")
		}
		filtered.Criterias = append(filtered.Criterias, fca)
	}

	for _, cn := range c.Criterions {
		fcn, err := cn.Accept(query, repositories)
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
		// Deliberately strict, unlike the other enum dispatches: AND/OR is a
		// closed boolean algebra with no growth pressure, an unknown operator
		// would silently suppress an entire criteria subtree (not just one
		// criterion), and if a non-monotone operator (e.g. negation) ever
		// were added, "skip as not affected" would no longer be provably
		// conservative. An out-of-vocabulary operator is data corruption or
		// a semantic change that must fail loudly.
		return false, errors.Errorf("unexpected criteria operator type. expected: %q, actual: %q", []CriteriaOperatorType{CriteriaOperatorTypeAND, CriteriaOperatorTypeOR}, c.Operator)
	}
}
