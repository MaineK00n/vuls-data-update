package cpecriterionrange_test

import (
	"testing"

	cpecRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestCompare(t *testing.T) {
	type args struct {
		x cpecRangeTypes.Range
		y cpecRangeTypes.Range
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
			if got := cpecRangeTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRange_Accept(t *testing.T) {
	tests := []struct {
		name    string
		r       cpecRangeTypes.Range
		v       string
		want    bool
		wantErr bool
	}{
		{name: "empty range matches anything", r: cpecRangeTypes.Range{}, v: "1.0.0", want: true},
		{name: "ge inclusive lower, equal", r: cpecRangeTypes.Range{GreaterEqual: "1.0.0"}, v: "1.0.0", want: true},
		{name: "ge inclusive lower, below", r: cpecRangeTypes.Range{GreaterEqual: "1.0.0"}, v: "0.9.9", want: false},
		{name: "gt exclusive lower, equal rejected", r: cpecRangeTypes.Range{GreaterThan: "1.0.0"}, v: "1.0.0", want: false},
		{name: "gt exclusive lower, above", r: cpecRangeTypes.Range{GreaterThan: "1.0.0"}, v: "1.0.1", want: true},
		{name: "le inclusive upper, equal", r: cpecRangeTypes.Range{LessEqual: "2.0.0"}, v: "2.0.0", want: true},
		{name: "le inclusive upper, above", r: cpecRangeTypes.Range{LessEqual: "2.0.0"}, v: "2.0.1", want: false},
		{name: "lt exclusive upper, equal rejected", r: cpecRangeTypes.Range{LessThan: "2.0.0"}, v: "2.0.0", want: false},
		{name: "lt exclusive upper, below", r: cpecRangeTypes.Range{LessThan: "2.0.0"}, v: "1.9.9", want: true},
		{name: "ge+lt window, in", r: cpecRangeTypes.Range{GreaterEqual: "1.0.0", LessThan: "2.0.0"}, v: "1.5.0", want: true},
		{name: "ge+lt window, below", r: cpecRangeTypes.Range{GreaterEqual: "1.0.0", LessThan: "2.0.0"}, v: "0.9.0", want: false},
		{name: "ge+lt window, at upper bound", r: cpecRangeTypes.Range{GreaterEqual: "1.0.0", LessThan: "2.0.0"}, v: "2.0.0", want: false},
		{name: "unparseable v yields false, no error", r: cpecRangeTypes.Range{LessThan: "2.0.0"}, v: "not-a-semver", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.r.Accept(tt.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
