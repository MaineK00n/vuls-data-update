package criterionpackage_test

import (
	"testing"

	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/package"
)

func TestCompare(t *testing.T) {
	type args struct {
		x criterionpackageTypes.Package
		y criterionpackageTypes.Package
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
			if got := criterionpackageTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackage_Accept(t *testing.T) {
	type fields struct {
		Name          string
		CPE           string
		Architectures []string
		Repositories  []string
		Functions     []string
	}
	type args struct {
		query criterionpackageTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "package 1",
			fields: fields{
				Name:          "package",
				Architectures: []string{"x86_64"},
				Repositories:  []string{"repository"},
				Functions:     []string{"function1", "function2"},
			},
			args: args{query: criterionpackageTypes.Query{
				Package: &criterionpackageTypes.QueryPackage{
					Name: "package",
				},
			}},
			want: true,
		},
		{
			name: "package 2",
			fields: fields{
				Name:          "package",
				Architectures: []string{"x86_64"},
				Repositories:  []string{"repository"},
				Functions:     []string{"function1", "function2"},
			},
			args: args{query: criterionpackageTypes.Query{
				Package: &criterionpackageTypes.QueryPackage{
					Name:       "package",
					Arch:       "x86_64",
					Repository: "repository",
					Functions:  []string{"function1"},
				},
			}},
			want: true,
		},
		{
			name: "package 3",
			fields: fields{
				Name: "package",
			},
			args: args{query: criterionpackageTypes.Query{
				Package: &criterionpackageTypes.QueryPackage{
					Name:       "package",
					Arch:       "x86_64",
					Repository: "repository",
					Functions:  []string{"function1"},
				},
			}},
			want: true,
		},
		{
			name: "package 4",
			fields: fields{
				Name:          "package",
				Architectures: []string{"x86_64"},
				Repositories:  []string{"repository"},
				Functions:     []string{"function1", "function2"},
			},
			args: args{query: criterionpackageTypes.Query{
				CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
			}},
			want: false,
		},
		{
			name: "cpe 1",
			fields: fields{
				CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: criterionpackageTypes.Query{
				CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
			}},
			want: true,
		},
		{
			name: "cpe 2",
			fields: fields{
				CPE: "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
			},
			args: args{query: criterionpackageTypes.Query{
				CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
			}},
			want: true,
		},
		{
			name: "cpe 3",
			fields: fields{
				Name: "package",
			},
			args: args{query: criterionpackageTypes.Query{
				CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
			}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := criterionpackageTypes.Package{
				Name:          tt.fields.Name,
				CPE:           tt.fields.CPE,
				Architectures: tt.fields.Architectures,
				Repositories:  tt.fields.Repositories,
				Functions:     tt.fields.Functions,
			}
			got, err := p.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Package.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Package.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
