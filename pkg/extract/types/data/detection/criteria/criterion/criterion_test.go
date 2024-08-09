package criterion_test

import (
	"reflect"
	"testing"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
)

func TestCompare(t *testing.T) {
	type args struct {
		x criterionTypes.Criterion
		y criterionTypes.Criterion
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
			if got := criterionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Vulnerable bool
		Package    packageTypes.Package
		Affected   *affectedTypes.Affected
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "vulnerable false",
			fields: fields{
				Vulnerable: false,
				Package:    packageTypes.Package{Name: "name"},
			},
			args: args{query: criterionTypes.Query{Package: &criterionTypes.QueryPackage{Name: "name"}}},
			want: false,
		},
		{
			name: "package 1",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{Name: "name"},
			},
			args: args{query: criterionTypes.Query{Package: &criterionTypes.QueryPackage{Name: "name"}}},
			want: true,
		},
		{
			name: "package 2",
			fields: fields{
				Vulnerable: true,
				Package: packageTypes.Package{
					Name:          "name",
					Architectures: []string{"x86_64"},
					Repositories:  []string{"repository"},
					Functions:     []string{"function1", "function2"},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeDPKG,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						Name:       "name",
						Version:    "0.0.0",
						Arch:       "x86_64",
						Repository: "repository",
						Functions:  []string{"function1", "function3"},
					},
				},
			},
			want: true,
		},
		{
			name: "package 3",
			fields: fields{
				Vulnerable: true,
				Package: packageTypes.Package{
					Name:          "name",
					Architectures: []string{"x86_64"},
					Repositories:  []string{"repository"},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeDPKG,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						Name:       "name",
						Version:    "0.0.2",
						Arch:       "x86_64",
						Repository: "repository",
					},
				},
			},
			want: false,
		},
		{
			name: "package 4",
			fields: fields{
				Vulnerable: true,
				Package: packageTypes.Package{
					Name: "name",
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeDPKG,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						Name:       "name",
						Version:    "0.0.0",
						Arch:       "x86_64",
						Repository: "repository",
						Functions:  []string{"function1"},
					},
				},
			},
			want: true,
		},
		{
			name: "package 5",
			fields: fields{
				Vulnerable: true,
				Package: packageTypes.Package{
					Name:          "name",
					Architectures: []string{"src"},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeDPKG,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						SrcName:    "name",
						SrcVersion: "0.0.0",
					},
				},
			},
			want: true,
		},
		{
			name: "package 6",
			fields: fields{
				Vulnerable: true,
				Package: packageTypes.Package{
					Name:          "name",
					Architectures: []string{"src"},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeDPKG,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{
						Name:    "name",
						Version: "0.0.0",
						Arch:    "x86_64",
					},
				},
			},
			want: false,
		},
		{
			name: "cpe 1",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }()}},
			want: true,
		},
		{
			name: "cpe 2",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeSEMVER,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }()}},
			want: true,
		},
		{
			name: "cpe 3",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeSEMVER,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
				},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.2:*:*:*:*:*:*:*"; return &s }()}},
			want: false,
		},
		{
			name: "cpe 4",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"; return &s }()}},
			want: true,
		},
		{
			name: "cpe 5",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }()}},
			want: false,
		},
		{
			name: "cpe 6",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }()}},
			want: true,
		},
		{
			name: "cpe 7",
			fields: fields{
				Vulnerable: true,
				Package:    packageTypes.Package{CPE: "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
			},
			args: args{query: criterionTypes.Query{CPE: func() *string { s := "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"; return &s }()}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criterionTypes.Criterion{
				Vulnerable: tt.fields.Vulnerable,
				Package:    tt.fields.Package,
				Affected:   tt.fields.Affected,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criterion.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Criterion.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
