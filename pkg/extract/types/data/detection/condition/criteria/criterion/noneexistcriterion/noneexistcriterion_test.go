package noneexistcriterion_test

import (
	"testing"

	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
)

func TestCompare(t *testing.T) {
	type args struct {
		x necTypes.Criterion
		y necTypes.Criterion
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
			if got := necTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Name string
		Arch string
	}
	type args struct {
		query necTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "installed",
			fields: fields{
				Name: "kpatch-patch-3_10_0-1062_4_1",
				Arch: "x86_64",
			},
			args: args{
				query: necTypes.Query{
					Binaries: []string{"kernel", "kpatch-patch-3_10_0-1062_4_1"},
				},
			},
			want: false,
		},
		{
			name: "not installed",
			fields: fields{
				Name: "kpatch-patch-3_10_0-1062_4_1",
				Arch: "x86_64",
			},
			args: args{
				query: necTypes.Query{
					Binaries: []string{"kernel"},
				},
			},
			want: true,
		},
		{
			name: "not installed 2",
			fields: fields{
				Name: "package",
				Arch: "src",
			},
			args: args{
				query: necTypes.Query{
					Binaries: []string{"package"},
					Sources:  []string{"spackage"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := necTypes.Criterion{
				Name: tt.fields.Name,
				Arch: tt.fields.Arch,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criterion.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Criterion.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
