package versoncriterion_test

import (
	"testing"

	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestCriterion_Sort(t *testing.T) {
	type fields struct {
		Vulnerable bool
		FixStatus  *fixstatusTypes.FixStatus
		Package    packageTypes.Package
		Affected   *affectedTypes.Affected
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &vcTypes.Criterion{
				Vulnerable: tt.fields.Vulnerable,
				FixStatus:  tt.fields.FixStatus,
				Package:    tt.fields.Package,
				Affected:   tt.fields.Affected,
			}
			c.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x vcTypes.Criterion
		y vcTypes.Criterion
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
			if got := vcTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Vulnerable bool
		FixStatus  *fixstatusTypes.FixStatus
		Package    packageTypes.Package
		Affected   *affectedTypes.Affected
	}
	type args struct {
		query vcTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "binary fixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{
						Name:          "name",
						Architectures: []string{"x86_64", "aarch64"},
						Repositories:  []string{"repo1", "repo2"},
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeRPM,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1-0.0.1.el9"}},
					Fixed: []string{"0.0.1-0.0.1.el9"},
				},
			},
			args: args{
				query: vcTypes.Query{
					Binary: &vcTypes.QueryBinary{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Arch:       "x86_64",
						Repository: "repo1",
					},
					Source: &vcTypes.QuerySource{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Repository: "repo1",
					},
				},
			},
			want: true,
		},
		{
			name: "binary unfixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnfixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeBinary,
					Binary: &binaryTypes.Package{
						Name:          "name",
						Architectures: []string{"x86_64", "aarch64"},
						Repositories:  []string{"repo1", "repo2"},
					},
				},
			},
			args: args{
				query: vcTypes.Query{
					Binary: &vcTypes.QueryBinary{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Arch:       "x86_64",
						Repository: "repo1",
					},
					Source: &vcTypes.QuerySource{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Repository: "repo1",
					},
				},
			},
			want: true,
		},
		{
			name: "source fixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeSource,
					Source: &sourceTypes.Package{
						Name:         "name",
						Repositories: []string{"repo1", "repo2"},
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeRPM,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1-0.0.1.el9"}},
					Fixed: []string{"0.0.1-0.0.1.el9"},
				},
			},
			args: args{
				query: vcTypes.Query{
					Binary: &vcTypes.QueryBinary{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Arch:       "x86_64",
						Repository: "repo1",
					},
					Source: &vcTypes.QuerySource{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Repository: "repo1",
					},
				},
			},
			want: true,
		},
		{
			name: "source unfixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnfixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeSource,
					Source: &sourceTypes.Package{
						Name:         "name",
						Repositories: []string{"repo1", "repo2"},
					},
				},
			},
			args: args{
				query: vcTypes.Query{
					Binary: &vcTypes.QueryBinary{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Arch:       "x86_64",
						Repository: "repo1",
					},
					Source: &vcTypes.QuerySource{
						Family:     ecosystemTypes.EcosystemTypeRedHat,
						Name:       "name",
						Version:    "0.0.1-0.0.0.el9",
						Repository: "repo1",
					},
				},
			},
			want: true,
		},
		{
			name: "cpe",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeCPE,
					CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeSEMVER,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.2"}},
				},
			},
			args: args{
				query: vcTypes.Query{
					CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"; return &s }(),
				},
			},
			want: true,
		},
		{
			name: "language fixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeLanguage,
					Language: &languageTypes.Package{
						Name:      "name",
						Functions: []string{"func1", "func2"},
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeNPM,
					Range: []affectedrangeTypes.Range{{LessThan: "0.0.1"}},
					Fixed: []string{"0.0.1"},
				},
			},
			args: args{
				query: vcTypes.Query{
					Language: &vcTypes.QueryLanguage{
						Ecosystem: ecosystemTypes.EcosystemTypeNpm,
						Name:      "name",
						Version:   "0.0.0",
						Functions: []string{"func1"},
					},
				},
			},
			want: true,
		},
		{
			name: "language unfixed",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeLanguage,
					Language: &languageTypes.Package{
						Name:      "name",
						Functions: []string{"func1", "func2"},
					},
				},
			},
			args: args{
				query: vcTypes.Query{
					Language: &vcTypes.QueryLanguage{
						Ecosystem: ecosystemTypes.EcosystemTypeNpm,
						Name:      "name",
						Version:   "0.0.0",
						Functions: []string{"func1"},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := vcTypes.Criterion{
				Vulnerable: tt.fields.Vulnerable,
				FixStatus:  tt.fields.FixStatus,
				Package:    tt.fields.Package,
				Affected:   tt.fields.Affected,
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
