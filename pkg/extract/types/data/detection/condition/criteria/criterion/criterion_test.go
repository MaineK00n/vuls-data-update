package criterion_test

import (
	"reflect"
	"testing"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
)

func TestCriterion_Sort(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
			}
			c.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x criterionTypes.Criterion
		y criterionTypes.Criterion
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
			if got := criterionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Contains(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
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
			c := criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
			}
			got, err := c.Contains(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criterion.Contains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Criterion.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    criterionTypes.FilteredCriterion
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criterion.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Criterion.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilteredCriterion_Affected(t *testing.T) {
	type fields struct {
		Criterion criterionTypes.Criterion
		Accepts   criterionTypes.AcceptQueries
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
			fc := criterionTypes.FilteredCriterion{
				Criterion: tt.fields.Criterion,
				Accepts:   tt.fields.Accepts,
			}
			got, err := fc.Affected()
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredCriterion.Affected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FilteredCriterion.Affected() = %v, want %v", got, tt.want)
			}
		})
	}
}
