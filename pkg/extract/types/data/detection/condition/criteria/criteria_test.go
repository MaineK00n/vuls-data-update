package criteria_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
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
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
								Name: "package2",
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
								Name: "package1",
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						CPE:       func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
					}},
				},
			},
			want: true,
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
										Name: "package2",
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
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
										Name: "package1",
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
								Name: "package2",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
										Name: "package1",
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
						Package: &vcTypes.QueryPackage{Name: "package1"},
					}},
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
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
									Name: "package1",
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
								Name: "package2",
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
									Name: "package2",
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
									Name: "package1",
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
								Name: "package1",
							},
						},
					},
					{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						CPE:       func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
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
									Name: "package1",
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
									CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
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
										Name: "package2",
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
								Name: "package1",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
											Name: "package2",
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
									Name: "package1",
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
										Name: "package1",
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
								Name: "package2",
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
											Name: "package1",
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
									Name: "package2",
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
										Name: "package1",
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
						Package: &vcTypes.QueryPackage{Name: "package1"},
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
											Name: "package1",
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
									Name: "package1",
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
									Name: "package1",
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
									Name: "package2",
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
									Name: "package1",
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
									Name: "package1",
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
									CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
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
									Name: "package1",
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
									CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
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
											Name: "package2",
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
									Name: "package1",
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
											Name: "package2",
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
									Name: "package1",
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
											Name: "package1",
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
											Name: "package2",
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
											Name: "package1",
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
											Name: "package2",
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
