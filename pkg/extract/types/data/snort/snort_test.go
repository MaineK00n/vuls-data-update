package snort_test

import (
	"testing"

	snortTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/snort"
)

func TestSnort_Sort(t *testing.T) {
	tests := []struct {
		name string
		s    *snortTypes.Snort
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &snortTypes.Snort{}
			s.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x snortTypes.Snort
		y snortTypes.Snort
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
			if got := snortTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
