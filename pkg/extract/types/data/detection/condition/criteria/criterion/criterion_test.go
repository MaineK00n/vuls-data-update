package criterion_test

import (
	"reflect"
	"testing"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestCriterion_Sort(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
			}
			c.Sort()
		})
	}
}

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

func TestCriterion_Contains(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
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
			name: "contains version",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &binaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
						Fixed: []string{"0.0.1-0.0.1.el9"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.0.el9",
							Arch:       "x86_64",
							Repository: "repo",
						},
						Source: &vcTypes.QuerySource{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.0.el9",
							Repository: "repo",
						},
					}},
				},
			},
			want: true,
		},
		{
			name: "not contains version",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &binaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
						Fixed: []string{"0.0.1-0.0.1.el9"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.2.el9",
							Arch:       "x86_64",
							Repository: "repo",
						},
						Source: &vcTypes.QuerySource{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.2.el9",
							Repository: "repo",
						},
					}},
				},
			},
			want: false,
		},
		{
			name: "contains none exist",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Name: "name",
					Arch: "x86_64",
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []string{"name2"},
						Sources:  []string{"name"},
					},
				},
			},
			want: true,
		},
		{
			name: "not contains none exist",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Name: "name",
					Arch: "x86_64",
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []string{"name"},
						Sources:  []string{"name"},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
			}
			got, err := c.Contains(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criterion.Contains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Criterion.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    criterionTypes.FilteredCriterion
		wantErr bool
	}{
		{
			name: "accept version",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &binaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
						Fixed: []string{"0.0.1-0.0.1.el9"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.0.el9",
							Arch:       "x86_64",
							Repository: "repo",
						},
						Source: &vcTypes.QuerySource{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.0.el9",
							Repository: "repo",
						},
					}},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &binaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
							Fixed: []string{"0.0.1-0.0.1.el9"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
			},
		},
		{
			name: "not accept version",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &binaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
						Fixed: []string{"0.0.1-0.0.1.el9"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.2.el9",
							Arch:       "x86_64",
							Repository: "repo",
						},
						Source: &vcTypes.QuerySource{
							Family:     ecosystemTypes.EcosystemTypeRedHat,
							Name:       "name",
							Version:    "0.0.1-0.0.2.el9",
							Repository: "repo",
						},
					}},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &binaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
							Fixed: []string{"0.0.1-0.0.1.el9"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{Version: nil},
			},
		},
		{
			name: "accept none exist",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Name: "name",
					Arch: "x86_64",
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []string{"name2"},
						Sources:  []string{"name"},
					},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeNoneExist,
					NoneExist: &necTypes.Criterion{
						Name: "name",
						Arch: "x86_64",
					},
				},
				Accepts: criterionTypes.AcceptQueries{NoneExist: true},
			},
		},
		{
			name: "accept none exist",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Name: "name",
					Arch: "x86_64",
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []string{"name"},
						Sources:  []string{"name"},
					},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeNoneExist,
					NoneExist: &necTypes.Criterion{
						Name: "name",
						Arch: "x86_64",
					},
				},
				Accepts: criterionTypes.AcceptQueries{NoneExist: false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
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

func TestFilteredCriterion_Affected(t *testing.T) {
	type fields struct {
		Criterion criterionTypes.Criterion
		Accepts   criterionTypes.AcceptQueries
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "affected version",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &binaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
							Fixed: []string{"0.0.1-0.0.1.el9"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
			},
			want: true,
		},
		{
			name: "not affected version",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &binaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
							Fixed: []string{"0.0.1-0.0.1.el9"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{Version: nil},
			},
			want: false,
		},
		{
			name: "affected none exist",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeNoneExist,
					NoneExist: &necTypes.Criterion{
						Name: "name",
						Arch: "x86_64",
					},
				},
				Accepts: criterionTypes.AcceptQueries{NoneExist: true},
			},
			want: true,
		},
		{
			name: "not affected none exist",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeNoneExist,
					NoneExist: &necTypes.Criterion{
						Name: "name",
						Arch: "x86_64",
					},
				},
				Accepts: criterionTypes.AcceptQueries{NoneExist: false},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := criterionTypes.FilteredCriterion{
				Criterion: tt.fields.Criterion,
				Accepts:   tt.fields.Accepts,
			}
			got, err := fc.Affected()
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredCriterion.Affected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FilteredCriterion.Affected() = %v, want %v", got, tt.want)
			}
		})
	}
}
