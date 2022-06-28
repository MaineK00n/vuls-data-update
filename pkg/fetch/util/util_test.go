package util_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

func TestUnique(t *testing.T) {
	type test[T comparable] struct {
		name string
		args []T
		want []T
	}
	tests := []test[int]{
		{
			name: "int",
			args: []int{1, 1, 2},
			want: []int{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, util.Unique(tt.args), cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Unique(). (-expected +got):\n%s", diff)
			}
		})
	}
}
