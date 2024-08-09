package affectedrange_test

import (
	"testing"

	affectedrange "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
)

func TestCompare(t *testing.T) {
	type args struct {
		x affectedrange.Range
		y affectedrange.Range
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
			if got := affectedrange.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRangeType_Compare(t *testing.T) {
	type args struct {
		v1 string
		v2 string
	}
	tests := []struct {
		name    string
		rt      affectedrange.RangeType
		args    args
		want    int
		wantErr bool
	}{
		{
			name:    "unknown type",
			rt:      affectedrange.RangeTypeUnknown,
			args:    args{v1: "awful-version", v2: "XXXX"},
			wantErr: true,
		},
		// TODO: Add more test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rt.Compare(tt.args.v1, tt.args.v2)
			if (err != nil) != tt.wantErr {
				t.Errorf("RangeType.Compare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RangeType.Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
