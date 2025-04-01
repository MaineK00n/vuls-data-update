package util_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"

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

func TestRemoveAll(t *testing.T) {
	type args struct {
		root string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				root: "happy",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), tt.args.root)
			if err := os.MkdirAll(d, 0750); err != nil {
				t.Error("unexpected error:", err)
			}

			if err := os.Mkdir(filepath.Join(d, ".git"), 0750); err != nil {
				t.Error("unexpected error:", err)
			}

			f, err := os.Create(filepath.Join(d, "README.md"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			defer f.Close() //nolint:errcheck

			f, err = os.Create(filepath.Join(d, "test.json"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			defer f.Close() //nolint:errcheck

			if err := util.RemoveAll(d); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			if _, err := os.Stat(filepath.Join(d, ".git")); errors.Is(err, fs.ErrNotExist) {
				t.Error(".git is not exist")
			}

			if _, err := os.Stat(filepath.Join(d, "README.md")); errors.Is(err, fs.ErrNotExist) {
				t.Error("README.md is not exist")
			}

			if _, err := os.Stat(filepath.Join(d, "test.json")); err == nil {
				t.Error("test.json is exist")
			}
		})
	}
}

func TestSplit(t *testing.T) {
	type args struct {
		str        string
		delimiters []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "",
			args: args{
				str:        "a-b-c",
				delimiters: []string{"-"},
			},
			want: []string{"a", "b-c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{"-", ":"},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{":", "-"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.Split(tt.args.str, tt.args.delimiters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Split() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Split(). (-expected +got):\n%s", diff)
			}
		})
	}
}
