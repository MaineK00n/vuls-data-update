package condition

import (
	"cmp"

	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Condition struct {
	Criteria criteriaTypes.Criteria    `json:"criteria,omitempty"`
	Tag      segmentTypes.DetectionTag `json:"tag,omitempty"`
}

func Compare(x, y Condition) int {
	return cmp.Compare(
		criteriaTypes.Compare(x.Criteria, y.Criteria),
		cmp.Compare(x.Tag, y.Tag),
	)
}

func (r *Condition) Sort() {
	r.Criteria.Sort()
}

func (c Condition) Contains(ecosystem ecosystemTypes.Ecosystem, query criterionTypes.Query) (bool, error) {
	isContained, err := c.Criteria.Contains(ecosystem, query)
	if err != nil {
		return false, errors.Wrap(err, "criteria contains")
	}
	return isContained, nil
}

func (c Condition) Accept(ecosystem ecosystemTypes.Ecosystem, queries []criterionTypes.Query) (FilteredCondition, error) {
	filtered, err := c.Criteria.Accept(ecosystem, queries)
	if err != nil {
		return FilteredCondition{}, errors.Wrap(err, "criteria accept")
	}
	return FilteredCondition{
		Criteria: filtered,
		Tag:      c.Tag,
	}, nil
}

type FilteredCondition struct {
	Criteria criteriaTypes.FilteredCriteria `json:"criteria,omitempty"`
	Tag      segmentTypes.DetectionTag      `json:"tag,omitempty"`
}

func (c FilteredCondition) Affected() (bool, error) {
	isAffected, err := c.Criteria.Affected()
	if err != nil {
		return false, errors.Wrap(err, "criteria affected")
	}
	return isAffected, nil
}
