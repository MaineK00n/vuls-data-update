package fixstatus_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/fixstatus"
)

func TestCompare(t *testing.T) {
	type args struct {
		x fixstatus.FixStatus
		y fixstatus.FixStatus
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
			if got := fixstatus.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
