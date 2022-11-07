package util_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
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

func TestBuildFilePath(t *testing.T) {
	type args struct {
		name     string
		compress string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "plain",
			args: args{
				name:     "name",
				compress: "",
			},
			want: "name",
		},
		{
			name: "gzip",
			args: args{
				name:     "name",
				compress: "gzip",
			},
			want: "name.gz",
		},
		{
			name: "bzip2",
			args: args{
				name:     "name",
				compress: "bzip2",
			},
			want: "name.bz2",
		},
		{
			name: "xz",
			args: args{
				name:     "name",
				compress: "xz",
			},
			want: "name.xz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := util.BuildFilePath(tt.args.name, tt.args.compress); got != tt.want {
				t.Errorf("BuildFilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
