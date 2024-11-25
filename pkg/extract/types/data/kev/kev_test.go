package kev_test

import (
	"testing"

	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
)

func TestCompare(t *testing.T) {
	type args struct {
		x kevTypes.KEV
		y kevTypes.KEV
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
			if got := kevTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
