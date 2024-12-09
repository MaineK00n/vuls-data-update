package criteria_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestCriteria_Sort(t *testing.T) {
	type fields struct {
		Operator   criteriaTypes.CriteriaOperatorType
		Criterias  []criteriaTypes.Criteria
		Criterions []criterionTypes.Criterion
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &criteriaTypes.Criteria{
				Operator:   tt.fields.Operator,
				Criterias:  tt.fields.Criterias,
				Criterions: tt.fields.Criterions,
			}
			c.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x criteriaTypes.Criteria
		y criteriaTypes.Criteria
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
			if got := criteriaTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriteria_Contains(t *testing.T) {
	type fields struct {
		Operator   criteriaTypes.CriteriaOperatorType
		Criterias  []criteriaTypes.Criteria
		Criterions []criterionTypes.Criterion
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
			name: "criterion 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: true,
		},
		{
			name: "criterion 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package2",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: true,
		},
		{
			name: "criterion 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeCPE,
								CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
					}},
				},
			},
			want: true,
		},
		{
			name: "criterion 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeNoneExist,
						NoneExist: &necTypes.Criterion{
							Name: "name",
							Arch: "x86_64",
						},
					},
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
			name: "criterion 5",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeNoneExist,
						NoneExist: &necTypes.Criterion{
							Name: "name",
							Arch: "x86_64",
						},
					},
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
		{
			name: "criteria 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package2",
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: true,
		},
		{
			name: "criteria 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: true,
		},
		{
			name: "criteria 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package2",
										},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: true,
		},
		{
			name: "criteria 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
									Affected: &affectedTypes.Affected{
										Type:  affectedrangeTypes.RangeTypeRPM,
										Range: []affectedrangeTypes.Range{{LessThan: "0.0.1.el9"}},
										Fixed: []string{"0.0.1.el9"},
									},
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeNoneExist,
								NoneExist: &necTypes.Criterion{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:  ecosystemTypes.EcosystemTypeRedHat,
							Name:    "package1",
							Version: "0.0.1.el9",
						},
					}},
					NoneExist: &necTypes.Query{
						Binaries: []string{"package1"},
						Sources:  []string{"package1"},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criteriaTypes.Criteria{
				Operator:   tt.fields.Operator,
				Criterias:  tt.fields.Criterias,
				Criterions: tt.fields.Criterions,
			}
			got, err := c.Contains(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criteria.Contains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Criteria.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriteria_Accept(t *testing.T) {
	type fields struct {
		Operator   criteriaTypes.CriteriaOperatorType
		Criterias  []criteriaTypes.Criteria
		Criterions []criterionTypes.Criterion
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    criteriaTypes.FilteredCriteria
		wantErr bool
	}{
		{
			name: "criterion 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
		},
		{
			name: "criterion 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package2",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package2",
									},
								},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: false,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
		},
		{
			name: "criterion 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeCPE,
								CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeCPE,
									CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
		},
		{
			name: "criterion 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeNoneExist,
						NoneExist: &necTypes.Criterion{
							Name: "name",
							Arch: "x86_64",
						},
					},
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
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
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
			},
		},
		{
			name: "criterion 5",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeNoneExist,
						NoneExist: &necTypes.Criterion{
							Name: "name",
							Arch: "x86_64",
						},
					},
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
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
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
			},
		},
		{
			name: "criteria 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package2",
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
		},
		{
			name: "criteria 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Type: criterionpackageTypes.PackageTypeBinary,
								Binary: &binaryTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
				},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package2",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "criteria 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package2",
										},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package1"},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "criteria 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Type: criterionpackageTypes.PackageTypeBinary,
										Binary: &binaryTypes.Package{
											Name: "package1",
										},
									},
									Affected: &affectedTypes.Affected{
										Type:  affectedrangeTypes.RangeTypeRPM,
										Range: []affectedrangeTypes.Range{{LessThan: "0.0.1.el9"}},
										Fixed: []string{"0.0.1.el9"},
									},
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeNoneExist,
								NoneExist: &necTypes.Criterion{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Family:  ecosystemTypes.EcosystemTypeRedHat,
							Name:    "package1",
							Version: "0.0.0.el9",
						},
					}},
					NoneExist: &necTypes.Query{
						Binaries: []string{"package1"},
						Sources:  []string{"package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{LessThan: "0.0.1.el9"}},
											Fixed: []string{"0.0.1.el9"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeNoneExist,
									NoneExist: &necTypes.Criterion{
										Name: "package2",
									},
								},
								Accepts: criterionTypes.AcceptQueries{NoneExist: true},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criteriaTypes.Criteria{
				Operator:   tt.fields.Operator,
				Criterias:  tt.fields.Criterias,
				Criterions: tt.fields.Criterions,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Criteria.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilteredCriteria_Affected(t *testing.T) {
	type fields struct {
		Operator   criteriaTypes.CriteriaOperatorType
		Criterias  []criteriaTypes.FilteredCriteria
		Criterions []criterionTypes.FilteredCriterion
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "criterion 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package2",
									},
								},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: false,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "criterion 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeCPE,
									CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 5",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeCPE,
									CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: false,
		},
		{
			name: "criterion 6",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
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
			},
			want: true,
		},
		{
			name: "criterion 7",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
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
			},
			want: false,
		},
		{
			name: "criteria 1",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
							},
						},
					},
				},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: true,
		},
		{
			name: "criteria 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Type: criterionpackageTypes.PackageTypeBinary,
									Binary: &binaryTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
			},
			want: false,
		},
		{
			name: "criteria 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "criteria 4",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "criteria 5",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackageTypes.Package{
											Type: criterionpackageTypes.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "package1",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{LessThan: "0.0.1.el9"}},
											Fixed: []string{"0.0.1.el9"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeNoneExist,
									NoneExist: &necTypes.Criterion{
										Name: "package2",
									},
								},
								Accepts: criterionTypes.AcceptQueries{NoneExist: true},
							},
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criteriaTypes.FilteredCriteria{
				Operator:   tt.fields.Operator,
				Criterias:  tt.fields.Criterias,
				Criterions: tt.fields.Criterions,
			}
			got, err := c.Affected()
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredCriteria.Affected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FilteredCriteria.Affected() = %v, want %v", got, tt.want)
			}
		})
	}
}
