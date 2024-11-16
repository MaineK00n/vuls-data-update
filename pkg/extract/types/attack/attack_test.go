package attack_test

import (
	"testing"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
)

func TestAttack_Sort(t *testing.T) {
	tests := []struct {
		name string
		d    *attackTypes.Attack
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &attackTypes.Attack{}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x attackTypes.Attack
		y attackTypes.Attack
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
			if got := attackTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
