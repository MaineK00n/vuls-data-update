package capec_test

import (
	"testing"

	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
)

func TestCAPEC_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *capecTypes.CAPEC
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &capecTypes.CAPEC{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x capecTypes.CAPEC
		y capecTypes.CAPEC
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
			if got := capecTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
