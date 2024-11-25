package condition_test

import (
	"reflect"
	"testing"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
)

func TestCondition_Sort(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			r.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x conditionTypes.Condition
		y conditionTypes.Condition
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conditionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_Contains(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			got, err := c.Contains(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Condition.Contains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Condition.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_Accept(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    conditionTypes.FilteredCondition
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Condition.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Condition.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilteredCondition_Affected(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.FilteredCriteria
		Tag      segmentTypes.DetectionTag
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.FilteredCondition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			got, err := c.Affected()
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredCondition.Affected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FilteredCondition.Affected() = %v, want %v", got, tt.want)
			}
		})
	}
}
