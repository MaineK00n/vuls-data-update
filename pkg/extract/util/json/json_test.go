package json_test

import (
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

var t1 = T1{ID: 42, Names: []string{"alice", "bob", "charlie"}}
var t2 = T2{ID: 42, Values: []int{1, 2, 3}}

func TestJsonReader(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		wants     []any
		wantPaths []string
	}{
		{
			name:      "empty",
			paths:     []string{},
			wants:     []any{},
			wantPaths: nil,
		},
		{
			name:      "one",
			paths:     []string{"./testdata/fixtures/t1.json"},
			wants:     []any{t1},
			wantPaths: []string{"./testdata/fixtures/t1.json"},
		},
		{
			name:      "two",
			paths:     []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json"},
			wants:     []any{t1, t2},
			wantPaths: []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json"},
		},
		{
			name:      "duplicated",
			paths:     []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json", "./testdata/fixtures/t1.json"},
			wants:     []any{t1, t2, t1},
			wantPaths: []string{"./testdata/fixtures/t1.json", "./testdata/fixtures/t2.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := utiljson.NewJSONReader()

			for i, p := range tt.paths {
				want := tt.wants[i]
				switch want.(type) {
				case T1:
					var t1 T1
					err := j.Read(p, &t1)
					if err != nil {
						t.Errorf("Read() error: %v", err)
						return
					}
					if diff := cmp.Diff(want, t1); diff != "" {
						t.Errorf("Read(). (-expected +got):\n%s", diff)
					}
				case T2:
					var t2 T2
					err := j.Read(p, &t2)
					if err != nil {
						t.Errorf("Read() error: %v", err)
						return
					}
					if diff := cmp.Diff(want, t2); diff != "" {
						t.Errorf("Read(). (-expected +got):\n%s", diff)
					}
				default:
					t.Errorf("Unexpected type. v: %v", want)
				}
			}

			if diff := cmp.Diff(tt.wantPaths, j.Paths(), cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("Paths(). (-expected +got):\n%s", diff)
			}
		})
	}

}

func TestReadJsonError(t *testing.T) {
	t.Run("not-pointer", func(t *testing.T) {
		j := utiljson.NewJSONReader()
		var t1 T1
		err := j.Read("./testdata/fixtures/t1.json", t1) // not a pointer, but pass t1 itself
		if err == nil {
			t.Errorf("should be error but not")
		}
	})
	t.Run("nil-pointer", func(t *testing.T) {
		j := utiljson.NewJSONReader()
		var t1 *T1
		err := j.Read("./testdata/fixtures/t1.json", t1) // nil pointer
		if err == nil {
			t.Errorf("should be error but not")
		}
	})
}
