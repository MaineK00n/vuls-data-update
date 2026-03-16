package util_test

import (
	"encoding/json/v2"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	windowskbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb"
	windowskbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/update"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
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
			defer f.Close()

			f, err = os.Create(filepath.Join(d, "test.json"))
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

func TestWrite(t *testing.T) {
	tests := []struct {
		name    string
		content any
		doSort  bool
		want    any
	}{
		{
			name: "windowskb.KB",
			content: windowskbTypes.KB{
				KBID: "5070881",
				Updates: []windowskbUpdateTypes.Update{
					{UpdateID: "bbb"},
					{UpdateID: "aaa"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"c.json", "a.json", "b.json"},
				},
			},
			doSort: true,
			want: windowskbTypes.KB{
				KBID: "5070881",
				Updates: []windowskbUpdateTypes.Update{
					{UpdateID: "aaa"},
					{UpdateID: "bbb"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"a.json", "b.json", "c.json"},
				},
			},
		},
		{
			name: "pointer type is not sorted",
			content: &windowskbTypes.KB{
				KBID: "5070881",
				Updates: []windowskbUpdateTypes.Update{
					{UpdateID: "bbb"},
					{UpdateID: "aaa"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"c.json", "a.json", "b.json"},
				},
			},
			doSort: true,
			want: windowskbTypes.KB{
				KBID: "5070881",
				Updates: []windowskbUpdateTypes.Update{
					{UpdateID: "bbb"},
					{UpdateID: "aaa"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"c.json", "a.json", "b.json"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out.json")
			if err := util.Write(path, tt.content, tt.doSort); err != nil {
				t.Fatal("unexpected error:", err)
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			defer f.Close()

			got := reflect.New(reflect.TypeOf(tt.want)).Interface()
			if err := json.UnmarshalRead(f, got); err != nil {
				t.Fatal("unexpected error:", err)
			}

			if diff := cmp.Diff(tt.want, reflect.ValueOf(got).Elem().Interface()); diff != "" {
				t.Errorf("Write(). (-expected +got):\n%s", diff)
			}
		})
	}
}
