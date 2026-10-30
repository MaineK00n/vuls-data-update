package criterion_test

import (
	"reflect"
	"testing"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
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

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Type      criterionTypes.CriterionType
		Version   *vcTypes.Criterion
		NoneExist *necTypes.Criterion
		KB        *kbcTypes.Criterion
		CPE       *ccTypes.Criterion
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
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
							Family:       ecosystemTypes.EcosystemTypeRedHat,
							Name:         "name",
							Version:      "0.0.1-0.0.0.el9",
							Arch:         "x86_64",
							Repositories: []string{"repo"},
						},
						Source: &vcTypes.QuerySource{
							Family:       ecosystemTypes.EcosystemTypeRedHat,
							Name:         "name",
							Version:      "0.0.1-0.0.0.el9",
							Repositories: []string{"repo"},
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
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
							Family:       ecosystemTypes.EcosystemTypeRedHat,
							Name:         "name",
							Version:      "0.0.1-0.0.2.el9",
							Arch:         "x86_64",
							Repositories: []string{"repo"},
						},
						Source: &vcTypes.QuerySource{
							Family:       ecosystemTypes.EcosystemTypeRedHat,
							Name:         "name",
							Version:      "0.0.1-0.0.2.el9",
							Repositories: []string{"repo"},
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
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
					Type: necTypes.PackageTypeBinary,
					Binary: &necBinaryPackageTypes.Package{
						Name:          "name",
						Architectures: []string{"x86_64"},
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
			want: criterionTypes.FilteredCriterion{
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
		{
			name: "accept none exist",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Type: necTypes.PackageTypeBinary,
					Binary: &necBinaryPackageTypes.Package{
						Name:          "name",
						Architectures: []string{"x86_64"},
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
			want: criterionTypes.FilteredCriterion{
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
		{
			name: "accept kb",
			fields: fields{
				Type: criterionTypes.CriterionTypeKB,
				KB: &kbcTypes.Criterion{
					Product: "Windows 10",
					KBID:    "5025239",
				},
			},
			args: args{
				query: criterionTypes.Query{
					KB: &kbcTypes.Query{
						AcceptProducts: []string{"Windows 10"},
						UnappliedKBs:   []string{"5025239", "5025305"},
					},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeKB,
					KB: &kbcTypes.Criterion{
						Product: "Windows 10",
						KBID:    "5025239",
					},
				},
				Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
			},
		},
		{
			name: "not accept kb",
			fields: fields{
				Type: criterionTypes.CriterionTypeKB,
				KB: &kbcTypes.Criterion{
					Product: "Windows 10",
					KBID:    "5025239",
				},
			},
			args: args{
				query: criterionTypes.Query{
					KB: &kbcTypes.Query{
						AcceptProducts: []string{"Windows 10"},
						UnappliedKBs:   []string{"5025305"},
					},
				},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeKB,
					KB: &kbcTypes.Criterion{
						Product: "Windows 10",
						KBID:    "5025239",
					},
				},
				Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{}},
			},
		},
		{
			name: "version criterion with query not set",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
						Fixed: []string{"0.0.1-0.0.1.el9"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{LessThan: "0.0.1-0.0.1.el9"}},
							Fixed: []string{"0.0.1-0.0.1.el9"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{},
			},
		},
		{
			name: "none exist criterion with query not set",
			fields: fields{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Type: necTypes.PackageTypeBinary,
					Binary: &necBinaryPackageTypes.Package{
						Name:          "name",
						Architectures: []string{"x86_64"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{},
			},
			want: criterionTypes.FilteredCriterion{
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
				Accepts: criterionTypes.AcceptQueries{},
			},
		},
		{
			name: "kb criterion with query not set",
			fields: fields{
				Type: criterionTypes.CriterionTypeKB,
				KB: &kbcTypes.Criterion{
					Product: "Windows 10",
					KBID:    "5025239",
				},
			},
			args: args{
				query: criterionTypes.Query{},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeKB,
					KB: &kbcTypes.Criterion{
						Product: "Windows 10",
						KBID:    "5025239",
					},
				},
				Accepts: criterionTypes.AcceptQueries{},
			},
		},
		{
			// No range could be derived, so an installed package is accepted
			// whatever its version, and recorded as version-unconfirmed.
			name: "accept unresolved version as version unconfirmed",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "Microsoft Office 2019 for 64-bit editions"},
					},
					Affected: &affectedTypes.Affected{
						Type:       affectedrangeType.RangeTypeUnresolved,
						Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{
						{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeMicrosoft, Name: "Windows 11 Version 24H2 for x64-based Systems", Version: "10.0.26100.1"}},
						{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeMicrosoft, Name: "Microsoft Office 2019 for 64-bit editions", Version: "16.0.10417.20030"}},
					},
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
							Binary: &vcBinaryPackageTypes.Package{Name: "Microsoft Office 2019 for 64-bit editions"},
						},
						Affected: &affectedTypes.Affected{
							Type:       affectedrangeType.RangeTypeUnresolved,
							Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{VersionUnconfirmed: []int{1}},
			},
		},
		{
			name: "not accept unresolved version of another package",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "Microsoft Office 2019 for 64-bit editions"},
					},
					Affected: &affectedTypes.Affected{
						Type:       affectedrangeType.RangeTypeUnresolved,
						Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{
						{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeMicrosoft, Name: "Microsoft Office 2019 for 32-bit editions", Version: "16.0.10417.20030"}},
					},
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
							Binary: &vcBinaryPackageTypes.Package{Name: "Microsoft Office 2019 for 64-bit editions"},
						},
						Affected: &affectedTypes.Affected{
							Type:       affectedrangeType.RangeTypeUnresolved,
							Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{},
			},
		},
		{
			// Type unresolved without Unresolved is a producer bug: an error,
			// not a warning.
			name: "unresolved range type without unresolved is an error",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{Type: affectedrangeType.RangeTypeUnresolved},
				},
			},
			args: args{
				query: criterionTypes.Query{
					Version: []vcTypes.Query{{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeMicrosoft, Name: "name", Version: "1.0.0"}}},
				},
			},
			wantErr: true,
		},
		{
			// A criterion type this build does not know (data from a newer
			// vuls-data-update) must accept no queries instead of aborting,
			// and the skip must be recorded on the result.
			name: "unsupported criterion type (newer data) accepts nothing",
			fields: fields{
				Type: criterionTypes.CriterionType("future-criterion"),
			},
			args: args{
				query: criterionTypes.Query{NoneExist: &necTypes.Query{}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
				Warnings:  []warningTypes.Warning{{Kind: warningTypes.KindUnevaluableCriterionType, Cause: "future-criterion"}},
			},
		},
		{
			// The layer that owns the data reports what it could not
			// evaluate; evaluation stops at the first blocker, so only the
			// package type surfaces here (the range type would surface once
			// the package type is understood).
			name: "version criterion with out-of-vocabulary package type records the first blocker",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					Package:    vcPackageTypes.Package{Type: vcPackageTypes.PackageType("future-package")},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeType("future-range"),
						Range: []affectedrangeType.Range{{LessThan: "1.0.0"}},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{Version: []vcTypes.Query{{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeRedHat, Name: "name", Version: "0.0.1"}}}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Package:    vcPackageTypes.Package{Type: vcPackageTypes.PackageType("future-package")},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeType("future-range"),
							Range: []affectedrangeType.Range{{LessThan: "1.0.0"}},
						},
					},
				},
				Warnings: []warningTypes.Warning{
					{Kind: warningTypes.KindUnevaluablePackageType, Cause: "future-package"},
				},
			},
		},
		{
			// With the package evaluable and matching, the unevaluable range
			// type is the blocker that surfaces.
			name: "version criterion with out-of-vocabulary range type records the skip",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeType("future-range"),
						Range: []affectedrangeType.Range{{LessThan: "1.0.0"}},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{Version: []vcTypes.Query{{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeRedHat, Name: "name", Version: "0.0.1", Arch: "x86_64"}}}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeType("future-range"),
							Range: []affectedrangeType.Range{{LessThan: "1.0.0"}},
						},
					},
				},
				Warnings: []warningTypes.Warning{
					{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"},
				},
			},
		},
		{
			// An endpoint-less Range element expresses nothing and cannot be
			// evaluated; the empty-range warning surfaces on the result.
			name: "version criterion with endpoint-less range records empty-range",
			fields: fields{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: "name"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeType.RangeTypeRPM,
						Range: []affectedrangeType.Range{{}},
					},
				},
			},
			args: args{
				query: criterionTypes.Query{Version: []vcTypes.Query{{Binary: &vcTypes.QueryBinary{Family: ecosystemTypes.EcosystemTypeRedHat, Name: "name", Version: "0.0.1", Arch: "x86_64"}}}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeType.RangeTypeRPM,
							Range: []affectedrangeType.Range{{}},
						},
					},
				},
				Warnings: []warningTypes.Warning{
					{Kind: warningTypes.KindEmptyRange},
				},
			},
		},
		{
			name: "none-exist criterion with out-of-vocabulary package type records the skip",
			fields: fields{
				Type:      criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{Type: necTypes.PackageType("future-package")},
			},
			args: args{
				query: criterionTypes.Query{NoneExist: &necTypes.Query{}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type:      criterionTypes.CriterionTypeNoneExist,
					NoneExist: &necTypes.Criterion{Type: necTypes.PackageType("future-package")},
				},
				Warnings: []warningTypes.Warning{{Kind: warningTypes.KindUnevaluablePackageType, Cause: "future-package"}},
			},
		},
		{
			// A warning the cpe criterion records itself (a pattern query
			// that skipped the Range) surfaces on the result next to the
			// accepted indexes of the other queries.
			name: "cpe criterion records the Range skipped for a pattern query",
			fields: fields{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
				},
			},
			args: args{
				query: criterionTypes.Query{CPE: []ccTypes.Query{
					{CPE: "cpe:2.3:a:vendor:product:12.5:*:*:*:*:*:*:*"},
					{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
				}},
			},
			want: criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &ccTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
					},
				},
				Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
				Warnings: []warningTypes.Warning{
					{Kind: warningTypes.KindPatternQueryRange, Cause: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := criterionTypes.Criterion{
				Type:      tt.fields.Type,
				Version:   tt.fields.Version,
				NoneExist: tt.fields.NoneExist,
				KB:        tt.fields.KB,
				CPE:       tt.fields.CPE,
			}
			got, err := c.Accept(tt.args.query, nil)
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
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
							Binary: &vcBinaryPackageTypes.Package{Name: "name"},
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
						Type: necTypes.PackageTypeBinary,
						Binary: &necBinaryPackageTypes.Package{
							Name:          "name",
							Architectures: []string{"x86_64"},
						},
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
						Type: necTypes.PackageTypeBinary,
						Binary: &necBinaryPackageTypes.Package{
							Name:          "name",
							Architectures: []string{"x86_64"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{NoneExist: false},
			},
			want: false,
		},
		{
			name: "affected kb",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeKB,
					KB: &kbcTypes.Criterion{
						Product: "Windows 10",
						KBID:    "5025239",
					},
				},
				Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
			},
			want: true,
		},
		{
			name: "not affected kb",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeKB,
					KB: &kbcTypes.Criterion{
						Product: "Windows 10",
						KBID:    "5025239",
					},
				},
				Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{}},
			},
			want: false,
		},
		{
			name: "affected version unconfirmed",
			fields: fields{
				Criterion: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusType.FixStatus{Class: fixstatusType.ClassFixed},
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{Name: "Microsoft Office 2019 for 64-bit editions"},
						},
						Affected: &affectedTypes.Affected{
							Type:       affectedrangeType.RangeTypeUnresolved,
							Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
						},
					},
				},
				Accepts: criterionTypes.AcceptQueries{VersionUnconfirmed: []int{0}},
			},
			want: true,
		},
		{
			// A criterion type this build does not know (data from a newer
			// vuls-data-update) must report not affected instead of aborting.
			name: "unsupported criterion type (newer data) is not affected",
			fields: fields{
				Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
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
