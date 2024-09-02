package json_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
)

func TestJSONReader_Read(t *testing.T) {
	type t1 struct {
		ID    int      `json:"id,omitempty"`
		Names []string `json:"names,omitempty"`
	}

	type args struct {
		path   string
		prefix string
		v      any
	}
	tests := []struct {
		name    string
		args    args
		want    any
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				path:   "./testdata/fixtures/t1.json",
				prefix: "./testdata",
				v:      &t1{},
			},
			want: &t1{
				ID:    42,
				Names: []string{"alice", "bob", "charlie"},
			},
		},
		{
			name: "not-pointer",
			args: args{
				path:   "./testdata/fixtures/t1.json",
				prefix: "./testdata",
				v:      t1{},
			},
			wantErr: true,
		},
		{
			name: "nil-pointer",
			args: args{
				path:   "./testdata/fixtures/t1.json",
				prefix: "./testdata",
				v:      func() *t1 { var t *t1; return t }(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := utiljson.NewJSONReader()
			if err := r.Read(tt.args.path, tt.args.prefix, tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("JSONReader.Read() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, tt.args.v); diff != "" {
				t.Errorf("Read(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestPaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{
			name:  "empty",
			paths: []string{},
			want:  nil,
		},
		{
			name:  "one",
			paths: []string{"./testdata/fixtures/t1.json"},
			want:  []string{"fixtures/t1.json"},
		},
		{
			name:  "two",
			paths: []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json"},
			want:  []string{"fixtures/t1.json", "fixtures/t2.json"},
		},
		{
			name:  "duplicated",
			paths: []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json", "./testdata/fixtures/t1.json"},
			want:  []string{"fixtures/t1.json", "fixtures/t2.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := utiljson.NewJSONReader()

			for _, p := range tt.paths {
				var target any
				err := r.Read(p, "testdata/fixtures", &target)
				if err != nil {
					t.Errorf("Read() error: %v", err)
					return
				}
			}
			fmt.Printf("%+v\n", reflect.TypeOf(r.Paths()))
			fmt.Printf("%+v\n", len(r.Paths()))

			if diff := cmp.Diff(tt.want, r.Paths(), cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("Paths(). (-expected +got):\n%s", diff)
			}
		})
	}
}
