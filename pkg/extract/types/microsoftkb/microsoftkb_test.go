package microsoftkb_test

import (
	"testing"

	microsoftKBTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
)

func TestMicrosoftKB_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *microsoftKBTypes.KB
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &microsoftKBTypes.KB{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x microsoftKBTypes.KB
		y microsoftKBTypes.KB
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
			if got := microsoftKBTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
