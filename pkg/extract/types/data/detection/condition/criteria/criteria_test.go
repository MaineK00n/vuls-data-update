package criteria_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/package"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

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
		ecosystem ecosystemTypes.Ecosystem
		query     criterionTypes.Query
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
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{Name: "package1"},
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
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package2",
						},
					},
					{
						Vulnerable: false,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{Name: "package1"},
				},
			},
			want: false,
		},
		{
			name: "criterion 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{Name: "package1"},
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package2",
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{Name: "package1"},
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Package: &criterionTypes.QueryPackage{Name: "package1"},
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
			got, err := c.Contains(tt.args.ecosystem, tt.args.query)
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
		ecosystem ecosystemTypes.Ecosystem
		queries   []criterionTypes.Query
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
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						Package: &criterionTypes.QueryPackage{Name: "package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
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
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package2",
						},
					},
					{
						Vulnerable: false,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						Package: &criterionTypes.QueryPackage{Name: "package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package2",
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
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
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						CPE: func() *string { s := "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"; return &s }(),
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							},
						},
						Accepts: []int{0},
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package1",
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						Package: &criterionTypes.QueryPackage{Name: "package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package2",
									},
								},
							},
						},
					},
				},
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
				},
				Criterions: []criterionTypes.Criterion{
					{
						Vulnerable: true,
						Package: criterionpackageTypes.Package{
							Name: "package2",
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						Package: &criterionTypes.QueryPackage{Name: "package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package1",
									},
								},
								Accepts: []int{0},
							},
						},
					},
				},
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package2",
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
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package1",
								},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Vulnerable: true,
								Package: criterionpackageTypes.Package{
									Name: "package2",
								},
							},
						},
					},
				},
			},
			args: args{
				queries: []criterionTypes.Query{
					{
						Package: &criterionTypes.QueryPackage{Name: "package1"},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package1",
									},
								},
								Accepts: []int{0},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criteriaTypes.Criteria{
				Operator:   tt.fields.Operator,
				Criterias:  tt.fields.Criterias,
				Criterions: tt.fields.Criterions,
			}
			got, err := c.Accept(tt.args.ecosystem, tt.args.queries)
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
		Criterions []criteriaTypes.FilteredCriterion
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
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 2",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 3",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package2",
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: false,
							Package: criterionpackageTypes.Package{
								Name: "package1",
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
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							},
						},
						Accepts: []int{0},
					},
				},
			},
			want: true,
		},
		{
			name: "criterion 5",
			fields: fields{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							},
						},
						Accepts: []int{0},
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
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package2",
									},
								},
								Accepts: []int{1},
							},
						},
					},
				},
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
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
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package2",
									},
								},
							},
						},
					},
				},
				Criterions: []criteriaTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Vulnerable: true,
							Package: criterionpackageTypes.Package{
								Name: "package1",
							},
						},
						Accepts: []int{0},
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
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package1",
									},
								},
								Accepts: []int{0},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package2",
									},
								},
								Accepts: []int{1},
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
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Vulnerable: true,
									Package: criterionpackageTypes.Package{
										Name: "package1",
									},
								},
								Accepts: []int{0},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criteriaTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
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
