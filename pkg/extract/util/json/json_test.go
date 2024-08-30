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

type T1 struct {
	ID    int      `json:"id,omitempty"`
	Names []string `json:"names,omitempty"`
}
type T2 struct {
	ID     int   `json:"id,omitempty"`
	Values []int `json:"values,omitempty"`
}

func TestRead(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		target any
		want   any
	}{
		{
			name:   "t1",
			path:   "./testdata/fixtures/t1.json",
			target: T1{},
			want:   T1{ID: 42, Names: []string{"alice", "bob", "charlie"}},
		},
		{
			name:   "t2",
			path:   "./testdata/fixtures/t2.json",
			target: T2{},
			want:   T2{ID: 42, Values: []int{1, 2, 3}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := utiljson.NewJSONReader()
			err := r.Read(tt.path, filepath.Base(tt.path), &tt.target)
			if err != nil {
				t.Errorf("Read() error: %v", err)
				return
			}
			if diff := cmp.Diff(tt.want, tt.want); diff != "" {
				t.Errorf("Read(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestReadError(t *testing.T) {
	t.Run("not-pointer", func(t *testing.T) {
		r := utiljson.NewJSONReader()
		var target T1
		err := r.Read("./testdata/fixtures/t1.json", "./testdata/fixtures", target) // not a pointer, but pass t1 itself
		if err == nil {
			t.Errorf("should be error but not")
		}
	})
	t.Run("nil-pointer", func(t *testing.T) {
		j := utiljson.NewJSONReader()
		var t1 *T1
		err := j.Read("./testdata/fixtures/t1.json", "./testdata/fixtures", t1) // nil pointer
		if err == nil {
			t.Errorf("should be error but not")
		}
	})
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
