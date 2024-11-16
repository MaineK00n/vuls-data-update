package cpe_test

import (
	"testing"

	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cpe"
)

func TestCPE_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *cpeTypes.CPE
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &cpeTypes.CPE{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x cpeTypes.CPE
		y cpeTypes.CPE
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
			if got := cpeTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
