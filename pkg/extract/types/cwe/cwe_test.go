package cwe_test

import (
	"testing"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
)

func TestCWE_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *cweTypes.CWE
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &cweTypes.CWE{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x cweTypes.CWE
		y cweTypes.CWE
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
			if got := cweTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
