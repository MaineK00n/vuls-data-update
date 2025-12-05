package util_test

import (
	"fmt"
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

			f, err := os.Create(filepath.Join(d, "test.json"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			defer f.Close()

			if err := util.RemoveAll(d); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			if _, err := os.Stat(filepath.Join(d, ".git")); errors.Is(err, fs.ErrNotExist) {
				t.Error(".git is not exist")
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

func TestWrite(t *testing.T) {
	type content struct {
		Message string `json:"message,omitempty"`
	}
	type args struct {
		path    string
		content any
		opts    []util.WriteOption
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				path:    "test.json",
				content: content{Message: "hello"},
			},
			want: []byte("{\n\t\"message\": \"hello\"\n}"),
		},
		{
			name: "invalid utf-8",
			args: args{
				path:    "test.json",
				content: content{Message: string([]byte{0x66, 0xfc, 0x72})},
			},
			want:    []byte{},
			wantErr: true,
		},
		{
			name: "allow invalid utf-8",
			args: args{
				path:    "test.json",
				content: content{Message: string([]byte{0x66, 0xfc, 0x72})},
				opts:    []util.WriteOption{util.WithAllowInvalidUTF8(true)},
			},
			want: []byte(fmt.Sprintf("{\n\t\"message\": \"%s\"\n}", string([]byte{0x66, 0xef, 0xbf, 0xbd, 0x72}))),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.args.path)
			if err := util.Write(path, tt.args.content, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Write(). (-expected +got):\n%s", diff)
			}
		})
	}
}
