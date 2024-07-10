package advisory_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
)

func TestCompare(t *testing.T) {
	type args struct {
		x advisory.Advisory
		y advisory.Advisory
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
			if got := advisory.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
