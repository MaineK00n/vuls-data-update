package criteria_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestCriteria_Sort(t *testing.T) {
	type fields struct {
		Operator     criteriaTypes.CriteriaOperatorType
		Criterias    []criteriaTypes.Criteria
		Criterions   []criterionTypes.Criterion
		Repositories []string
	}
	tests := []struct {
		name   string
		fields fields
		want   criteriaTypes.Criteria
	}{
		{
			name: "repositories sorted",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo3", "repo1", "repo2"},
			},
			want: criteriaTypes.Criteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo1", "repo2", "repo3"},
			},
		},
		{
			name: "nested repositories sorted",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"z-repo", "a-repo"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator:     criteriaTypes.CriteriaOperatorTypeOR,
						Repositories: []string{"c-repo", "b-repo"},
					},
				},
			},
			want: criteriaTypes.Criteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"a-repo", "z-repo"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator:     criteriaTypes.CriteriaOperatorTypeOR,
						Repositories: []string{"b-repo", "c-repo"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &criteriaTypes.Criteria{
				Operator:     tt.fields.Operator,
				Criterias:    tt.fields.Criterias,
				Criterions:   tt.fields.Criterions,
				Repositories: tt.fields.Repositories,
			}
			c.Sort()
			if diff := cmp.Diff(tt.want, *c); diff != "" {
				t.Errorf("Sort(). (-expected +got):\n%s", diff)
			}
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
		{
			name: "equal with same repositories",
			args: args{
				x: criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"repo1", "repo2"},
				},
				y: criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"repo1", "repo2"},
				},
			},
			want: 0,
		},
		{
			name: "different repositories",
			args: args{
				x: criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"repo1"},
				},
				y: criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"repo2"},
				},
			},
			want: -1,
		},
		{
			name: "nil vs non-nil repositories",
			args: args{
				x: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
				},
				y: criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"repo1"},
				},
			},
			want: -1,
		},
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
		query              criterionTypes.Query
		parentRepositories []string
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeCPE,
								CPE:  new(cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")),
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						CPE: new("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
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
							Type: necTypes.PackageTypeBinary,
							Binary: &necBinaryPackageTypes.Package{
								Name:          "name",
								Architectures: []string{"x86_64"},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "name2"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "name"}},
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
							Type: necTypes.PackageTypeBinary,
							Binary: &necBinaryPackageTypes.Package{
								Name:          "name",
								Architectures: []string{"x86_64"},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "name"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "name"}},
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
									Type: necTypes.PackageTypeBinary,
									Binary: &necBinaryPackageTypes.Package{
										Name: "package2",
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
						Binary: &vcTypes.QueryBinary{
							Family:  ecosystemTypes.EcosystemTypeRedHat,
							Name:    "package1",
							Version: "0.0.1.el9",
						},
					}},
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "package1"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "package1"}},
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
			got, err := c.Contains(tt.args.query, tt.args.parentRepositories)
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
		Operator     criteriaTypes.CriteriaOperatorType
		Criterias    []criteriaTypes.Criteria
		Criterions   []criterionTypes.Criterion
		Repositories []string
	}
	type args struct {
		query        criterionTypes.Query
		repositories []string
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeCPE,
								CPE:  new(cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")),
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						CPE: new("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeCPE,
									CPE:  new(cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")),
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
							Type: necTypes.PackageTypeBinary,
							Binary: &necBinaryPackageTypes.Package{
								Name:          "name",
								Architectures: []string{"x86_64"},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "name2"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "name"}},
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
								Type: necTypes.PackageTypeBinary,
								Binary: &necBinaryPackageTypes.Package{
									Name:          "name",
									Architectures: []string{"x86_64"},
								},
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
							Type: necTypes.PackageTypeBinary,
							Binary: &necBinaryPackageTypes.Package{
								Name:          "name",
								Architectures: []string{"x86_64"},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "name"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "name"}},
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
								Type: necTypes.PackageTypeBinary,
								Binary: &necBinaryPackageTypes.Package{
									Name:          "name",
									Architectures: []string{"x86_64"},
								},
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
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
									Type: necTypes.PackageTypeBinary,
									Binary: &necBinaryPackageTypes.Package{
										Name: "package2",
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
						Binary: &vcTypes.QueryBinary{
							Family:  ecosystemTypes.EcosystemTypeRedHat,
							Name:    "package1",
							Version: "0.0.0.el9",
						},
					}},
					NoneExist: &necTypes.Query{
						Binaries: []necBinaryPackageTypes.Query{{Name: "package1"}},
						Sources:  []necSourcePackageTypes.Query{{Name: "package1"}},
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Type: necTypes.PackageTypeBinary,
										Binary: &necBinaryPackageTypes.Package{
											Name: "package2",
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{NoneExist: true},
							},
						},
					},
				},
			},
		},
		{
			name: "repositories propagated from parent to criterions",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo1", "repo2"},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"repo1"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo1", "repo2"},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
			name: "repositories propagated from parent to child criteria",
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
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "package1",
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"repo1"},
						},
					}},
				},
				repositories: []string{"repo1", "repo2"},
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
			},
		},
		{
			name: "child repositories override parent",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"parent-repo"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator:     criteriaTypes.CriteriaOperatorTypeOR,
						Repositories: []string{"child-repo"},
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "package1",
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"child-repo"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"parent-repo"},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator:     criteriaTypes.CriteriaOperatorTypeOR,
						Repositories: []string{"child-repo"},
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
			},
		},
		{
			name: "repository mismatch rejects criterion",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo1"},
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"other-repo"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"repo1"},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "package1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{},
					},
				},
			},
		},
		{
			name: "grandchild inherits parent when child has no repositories",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"root-repo"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterias: []criteriaTypes.Criteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.Criterion{
									{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &vcTypes.Criterion{
											Vulnerable: true,
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "package1",
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
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"root-repo"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"root-repo"},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
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
					},
				},
			},
		},
		{
			name: "inherited repositories mismatch rejects criterion",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"repo1"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "package1",
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"other-repo"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"repo1"},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "package1",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{},
							},
						},
					},
				},
			},
		},
		{
			name: "amazon kernel6.12 AND guard: host without kernel6.12",
			fields: fields{
				// OR(
				//   kernel6.12 (version criterion),
				//   AND(
				//     kernel6.12 >= 0 (vulnerable:false, guard),
				//     OR(kernel-tools (version criterion))
				//   )
				// )
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "kernel6.12",
								},
							},
							Affected: &affectedTypes.Affected{
								Type:  affectedrangeTypes.RangeTypeRPM,
								Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
								Fixed: []string{"0:6.12.6-1.amzn2023"},
							},
						},
					},
				},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: false,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "kernel6.12",
										},
									},
									Affected: &affectedTypes.Affected{
										Type:  affectedrangeTypes.RangeTypeRPM,
										Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
									},
								},
							},
						},
						Criterias: []criteriaTypes.Criteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.Criterion{
									{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &vcTypes.Criterion{
											Vulnerable: true,
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "kernel-tools",
												},
											},
											Affected: &affectedTypes.Affected{
												Type:  affectedrangeTypes.RangeTypeRPM,
												Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
												Fixed: []string{"0:6.12.6-1.amzn2023"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				// Host runs kernel 6.1 (has kernel + kernel-tools, but NOT kernel6.12)
				query: criterionTypes.Query{
					Version: []vcTypes.Query{
						{
							Binary: &vcTypes.QueryBinary{
								Name:    "kernel",
								Version: "0:6.1.100-1.amzn2023",
							},
						},
						{
							Binary: &vcTypes.QueryBinary{
								Name:    "kernel-tools",
								Version: "0:6.1.100-1.amzn2023",
							},
						},
					},
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel6.12",
									},
								},
								Affected: &affectedTypes.Affected{
									Type:  affectedrangeTypes.RangeTypeRPM,
									Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
									Fixed: []string{"0:6.12.6-1.amzn2023"},
								},
							},
						},
					},
				},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: false,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "kernel6.12",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
										},
									},
								},
							},
						},
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "kernel-tools",
													},
												},
												Affected: &affectedTypes.Affected{
													Type:  affectedrangeTypes.RangeTypeRPM,
													Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
													Fixed: []string{"0:6.12.6-1.amzn2023"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "amazon kernel6.12 AND guard: host with kernel6.12",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: "kernel6.12",
								},
							},
							Affected: &affectedTypes.Affected{
								Type:  affectedrangeTypes.RangeTypeRPM,
								Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
								Fixed: []string{"0:6.12.6-1.amzn2023"},
							},
						},
					},
				},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: false,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "kernel6.12",
										},
									},
									Affected: &affectedTypes.Affected{
										Type:  affectedrangeTypes.RangeTypeRPM,
										Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
									},
								},
							},
						},
						Criterias: []criteriaTypes.Criteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.Criterion{
									{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &vcTypes.Criterion{
											Vulnerable: true,
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "kernel-tools",
												},
											},
											Affected: &affectedTypes.Affected{
												Type:  affectedrangeTypes.RangeTypeRPM,
												Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
												Fixed: []string{"0:6.12.6-1.amzn2023"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				// Host has both kernel6.12 and kernel-tools
				query: criterionTypes.Query{
					Version: []vcTypes.Query{
						{
							Binary: &vcTypes.QueryBinary{
								Name:    "kernel6.12",
								Version: "0:6.12.3-1.amzn2023",
							},
						},
						{
							Binary: &vcTypes.QueryBinary{
								Name:    "kernel-tools",
								Version: "0:6.12.3-1.amzn2023",
							},
						},
					},
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel6.12",
									},
								},
								Affected: &affectedTypes.Affected{
									Type:  affectedrangeTypes.RangeTypeRPM,
									Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
									Fixed: []string{"0:6.12.6-1.amzn2023"},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: false,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "kernel6.12",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "kernel-tools",
													},
												},
												Affected: &affectedTypes.Affected{
													Type:  affectedrangeTypes.RangeTypeRPM,
													Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
													Fixed: []string{"0:6.12.6-1.amzn2023"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "child FilteredCriteria does not inherit parent Repositories",
			fields: fields{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"parent-repo"},
				Criterias: []criteriaTypes.Criteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "package1",
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
						Binary: &vcTypes.QueryBinary{
							Name:         "package1",
							Repositories: []string{"parent-repo"},
						},
					}},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeAND,
				Repositories: []string{"parent-repo"},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criteriaTypes.Criteria{
				Operator:     tt.fields.Operator,
				Criterias:    tt.fields.Criterias,
				Criterions:   tt.fields.Criterions,
				Repositories: tt.fields.Repositories,
			}
			got, err := c.Accept(tt.args.query, tt.args.repositories)
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeCPE,
									CPE:  new(cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")),
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeCPE,
									CPE:  new(cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")),
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
								Type: necTypes.PackageTypeBinary,
								Binary: &necBinaryPackageTypes.Package{
									Name:          "name",
									Architectures: []string{"x86_64"},
								},
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
								Type: necTypes.PackageTypeBinary,
								Binary: &necBinaryPackageTypes.Package{
									Name:          "name",
									Architectures: []string{"x86_64"},
								},
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
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
										Type: necTypes.PackageTypeBinary,
										Binary: &necBinaryPackageTypes.Package{
											Name: "package2",
										},
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
		{
			name: "amazon kernel6.12 AND guard: host without kernel6.12 - not affected",
			fields: fields{
				// OR(
				//   kernel6.12 (no Accepts - not installed),
				//   AND(
				//     kernel6.12 guard (no Accepts - not installed),
				//     OR(kernel-tools (Accepts - installed & vulnerable))
				//   )
				// )
				// The AND branch fails because the guard criterion has no Accepts,
				// so the overall OR tree is not affected.
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel6.12",
									},
								},
								Affected: &affectedTypes.Affected{
									Type:  affectedrangeTypes.RangeTypeRPM,
									Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
									Fixed: []string{"0:6.12.6-1.amzn2023"},
								},
							},
						},
					},
				},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: false,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "kernel6.12",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
										},
									},
								},
								// No Accepts: kernel6.12 is not installed on this host
							},
						},
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "kernel-tools",
													},
												},
												Affected: &affectedTypes.Affected{
													Type:  affectedrangeTypes.RangeTypeRPM,
													Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
													Fixed: []string{"0:6.12.6-1.amzn2023"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
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
			name: "amazon kernel6.12 AND guard: host with kernel6.12 - affected",
			fields: fields{
				// OR(
				//   kernel6.12 (Accepts - installed & vulnerable),
				//   AND(
				//     kernel6.12 guard (Accepts - installed),
				//     OR(kernel-tools (Accepts - installed & vulnerable))
				//   )
				// )
				// Both the top-level criterion and the AND branch are satisfied.
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel6.12",
									},
								},
								Affected: &affectedTypes.Affected{
									Type:  affectedrangeTypes.RangeTypeRPM,
									Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
									Fixed: []string{"0:6.12.6-1.amzn2023"},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
					},
				},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: false,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "kernel6.12",
											},
										},
										Affected: &affectedTypes.Affected{
											Type:  affectedrangeTypes.RangeTypeRPM,
											Range: []affectedrangeTypes.Range{{GreaterEqual: "0"}},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							},
						},
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "kernel-tools",
													},
												},
												Affected: &affectedTypes.Affected{
													Type:  affectedrangeTypes.RangeTypeRPM,
													Range: []affectedrangeTypes.Range{{LessThan: "0:6.12.6-1.amzn2023"}},
													Fixed: []string{"0:6.12.6-1.amzn2023"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
									},
								},
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
