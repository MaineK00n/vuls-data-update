package noneexistcriterion_test

import (
	"testing"

	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
)

func TestCriterion_Sort(t *testing.T) {
	type fields struct {
		Type   necTypes.PackageType
		Binary *binaryTypes.Package
		Source *sourceTypes.Package
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &necTypes.Criterion{
				Type:   tt.fields.Type,
				Binary: tt.fields.Binary,
				Source: tt.fields.Source,
			}
			c.Sort()
		})
	}
}

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
		Type   necTypes.PackageType
		Binary *binaryTypes.Package
		Source *sourceTypes.Package
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
				Type: necTypes.PackageTypeBinary,
				Binary: &binaryTypes.Package{
					Name:          "kpatch-patch-3_10_0-1062_4_1",
					Architectures: []string{"x86_64", "aarch64"},
					Repositories:  []string{"repo1"},
				},
			},
			args: args{
				query: necTypes.Query{
					Binaries: []binaryTypes.Query{
						{
							Name:       "kernel",
							Arch:       "x86_64",
							Repository: "repo1",
						},
						{
							Name:       "kpatch-patch-3_10_0-1062_4_1",
							Arch:       "x86_64",
							Repository: "repo1",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "not installed 1",
			fields: fields{
				Type: necTypes.PackageTypeBinary,
				Binary: &binaryTypes.Package{
					Name:          "kpatch-patch-3_10_0-1062_4_1",
					Architectures: []string{"x86_64", "aarch64"},
					Repositories:  []string{"repo1"},
				},
			},
			args: args{
				query: necTypes.Query{
					Binaries: []binaryTypes.Query{
						{
							Name:       "kernel",
							Arch:       "x86_64",
							Repository: "repo1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "not installed 2",
			fields: fields{
				Type: necTypes.PackageTypeBinary,
				Binary: &binaryTypes.Package{
					Name:          "kpatch-patch-3_10_0-1062_4_1",
					Architectures: []string{"x86_64", "aarch64"},
					Repositories:  []string{"repo1"},
				},
			},
			args: args{
				query: necTypes.Query{
					Binaries: []binaryTypes.Query{
						{
							Name:       "kernel",
							Arch:       "x86_64",
							Repository: "repo2",
						},
						{
							Name:       "kpatch-patch-3_10_0-1062_4_1",
							Arch:       "x86_64",
							Repository: "repo2",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "not installed 3",
			fields: fields{
				Type: necTypes.PackageTypeSource,
				Source: &sourceTypes.Package{
					Name: "package",
				},
			},
			args: args{
				query: necTypes.Query{
					Binaries: []binaryTypes.Query{{Name: "package"}},
					Sources:  []sourceTypes.Query{{Name: "srcpackage"}},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := necTypes.Criterion{
				Type:   tt.fields.Type,
				Binary: tt.fields.Binary,
				Source: tt.fields.Source,
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
