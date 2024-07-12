package cwe_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
)

func TestCompare(t *testing.T) {
	type args struct {
		x cwe.CWE
		y cwe.CWE
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
			if got := cwe.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
