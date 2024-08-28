package source_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

func TestCompare(t *testing.T) {
	type args struct {
		x source.Source
		y source.Source
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
			if got := source.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
