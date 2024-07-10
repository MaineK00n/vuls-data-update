package criteria_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
)

func TestCompare(t *testing.T) {
	type args struct {
		x criteria.Criteria
		y criteria.Criteria
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
			if got := criteria.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
