package windowskb_test

import (
	"testing"

	windowsKBTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb"
)

func TestWindowsKB_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *windowsKBTypes.WindowsKB
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &windowsKBTypes.WindowsKB{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x windowsKBTypes.WindowsKB
		y windowsKBTypes.WindowsKB
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
			if got := windowsKBTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
