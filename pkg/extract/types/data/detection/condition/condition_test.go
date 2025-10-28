package condition_test

import (
	"fmt"
	"reflect"
	"testing"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
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
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/google/go-cmp/cmp"
)

func TestCondition_Sort(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			r.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x conditionTypes.Condition
		y conditionTypes.Condition
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
			if got := conditionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_Contains(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
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
			name: "contains",
			fields: fields{
				Criteria: criteriaTypes.Criteria{
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
				Tag: segmentTypes.DetectionTag("tag"),
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
			name: "not contains",
			fields: fields{
				Criteria: criteriaTypes.Criteria{
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
				Tag: segmentTypes.DetectionTag("tag"),
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{
						Binary: &vcTypes.QueryBinary{Name: "package"},
					}},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			got, err := c.Contains(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Condition.Contains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Condition.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_Accept(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.Criteria
		Tag      segmentTypes.DetectionTag
	}
	type args struct {
		query criterionTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    conditionTypes.FilteredCondition
		wantErr bool
	}{
		{
			name: "accept",
			fields: fields{
				Criteria: criteriaTypes.Criteria{
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
				Tag: segmentTypes.DetectionTag("tag"),
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
			want: conditionTypes.FilteredCondition{
				Criteria: criteriaTypes.FilteredCriteria{
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
				Tag: segmentTypes.DetectionTag("tag"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.Condition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Condition.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Condition.Accept() mismatch (-want +got):\n%s", diff)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Condition.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilteredCondition_Affected(t *testing.T) {
	type fields struct {
		Criteria criteriaTypes.FilteredCriteria
		Tag      segmentTypes.DetectionTag
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "affected",
			fields: fields{
				Criteria: criteriaTypes.FilteredCriteria{
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
				Tag: segmentTypes.DetectionTag("tag"),
			},
			want: true,
		},
		{
			name: "not affected",
			fields: fields{
				Criteria: criteriaTypes.FilteredCriteria{
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
										Type: criterionTypes.CriterionTypeNoneExist,
										NoneExist: &necTypes.Criterion{
											Type: necTypes.PackageTypeBinary,
											Binary: &necBinaryPackageTypes.Package{
												Name: "package1",
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{NoneExist: false},
								},
							},
						},
					},
				},
				Tag: segmentTypes.DetectionTag("tag"),
			},
			want: false,
		},
		{
			name: "OR - AND - {OR1, OR2}, OR1 is not satisfied",
			fields: fields{
				Criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: false,
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "product1-release",
														},
													},
													Affected: &affectedTypes.Affected{
														Type:  affectedrangeTypes.RangeTypeRPMVersionOnly,
														Range: []affectedrangeTypes.Range{{Equal: "0.0.1"}},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: nil,
											},
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
															Name: "package1",
														},
													},
													Affected: &affectedTypes.Affected{
														Type:  affectedrangeTypes.RangeTypeRPM,
														Range: []affectedrangeTypes.Range{{LessThan: "0.0.1-1"}},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: false,
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "product1-release",
														},
													},
													Affected: &affectedTypes.Affected{
														Type:  affectedrangeTypes.RangeTypeRPMVersionOnly,
														Range: []affectedrangeTypes.Range{{Equal: "0.0.2"}},
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
															Name: "package1",
														},
													},
													Affected: &affectedTypes.Affected{
														Type:  affectedrangeTypes.RangeTypeRPM,
														Range: []affectedrangeTypes.Range{{LessThan: "0.0.1-1"}},
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
				Tag: segmentTypes.DetectionTag("tag"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := conditionTypes.FilteredCondition{
				Criteria: tt.fields.Criteria,
				Tag:      tt.fields.Tag,
			}
			c2 := &c
			got, err := c2.Affected()
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredCondition.Affected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Printf("======= c2: %+v\n", c2)

			if got != tt.want {
				t.Errorf("FilteredCondition.Affected() = %v, want %v", got, tt.want)
			}
		})
	}
}
