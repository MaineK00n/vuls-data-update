package affectedrange_test

import (
	"testing"

	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestCompare(t *testing.T) {
	type args struct {
		x affectedrangeTypes.Range
		y affectedrangeTypes.Range
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
			if got := affectedrangeTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRangeType_Compare(t *testing.T) {
	type args struct {
		family ecosystemTypes.Ecosystem
		v1     string
		v2     string
	}
	tests := []struct {
		name    string
		rt      affectedrangeTypes.RangeType
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "centos v1: non centos package, v2: non centos package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.el8",
			},
			want: 0,
		},
		{
			name: "centos v1: centos package, v2: non centos package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.el8.centos",
				v2:     "0.0.1-0.0.1.el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.module_el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.module_el8",
				v2:     "0.0.1-0.0.1.module_el8",
			},
			want: 0,
		},
		{
			name: "centos v1: el7, v2: el8",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.el7",
				v2:     "0.0.1-0.0.1.el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: el8, v2: el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.el8_10",
			},
			want: -1,
		},
		{
			name: "centos v1: module+el8, v2: module+el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosytemCentOS,
				v1:     "0.0.1-0.0.1.module+el8",
				v2:     "0.0.1-0.0.1.module+el8_10",
			},
			want: -1,
		},
		{
			name: "alma v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeAlma,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "alma v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeAlma,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.module_el9",
			},
			wantErr: true,
		},
		{
			name: "alma v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeAlma,
				v1:     "0.0.1-0.0.1.module_el9",
				v2:     "0.0.1-0.0.1.module_el9",
			},
			want: 0,
		},
		{
			name: "rocky v1: rocky, v2: rocky",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRocky,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "rocky v1: rocky sig cloud, v2: rocky",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRocky,
				v1:     "0.0.1-0.0.1.el9.cloud.0",
				v2:     "0.0.1-0.0.1.el9",
			},
			wantErr: true,
		},
		{
			name: "rocky v1: rocky sig cloud, v2: rocky sig cloud",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRocky,
				v1:     "0.0.1-0.0.1.el9.cloud.0",
				v2:     "0.0.1-0.0.1.el9.cloud.0.1",
			},
			want: -1,
		},
		{
			name: "rocky v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRocky,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "rocky v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRocky,
				v1:     "0.0.1-0.0.1.module+el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: not ksplice, v2: not ksplice",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: not ksplice, v2: ksplice1",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.ksplice1.el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: ksplice1, v2: ksplice1",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.ksplice1.el9",
				v2:     "0.0.1-0.0.1.ksplice1.el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: ksplice1, v2: ksplice2",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.ksplice1.el9",
				v2:     "0.0.1-0.0.1.ksplice2.el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: non fips, v2: fips",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.el9_fips",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: fips, v2: fips",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.el9_fips",
				v2:     "0.0.1-0.0.1.el9_fips",
			},
			want: 0,
		},
		{
			name: "oracle v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeOracle,
				v1:     "0.0.1-0.0.1.module+el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "fedora v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeFedora,
				v1:     "0.0.1-0.0.1.fc35",
				v2:     "0.0.1-0.0.1.fc35",
			},
			want: 0,
		},
		{
			name: "fedora v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeFedora,
				v1:     "0.0.1-0.0.1.fc35",
				v2:     "0.0.1-0.0.1.module_f35",
			},
			wantErr: true,
		},
		{
			name: "fedora v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeFedora,
				v1:     "0.0.1-0.0.1.module_f35",
				v2:     "0.0.1-0.0.1.module_f35",
			},
			want: 0,
		},
		{
			name: "redhat v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "redhat v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "redhat v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.module+el9",
				v2:     "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "redhat v1: el7, v2: el8",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.el7",
				v2:     "0.0.1-0.0.1.el8",
			},
			wantErr: true,
		},
		{
			name: "redhat v1: el8, v2: el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.el8_10",
			},
			want: -1,
		},
		{
			name: "redhat v1: el8, v2: el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.2.el8_0",
				v2:     "0.0.1-0.0.1.el8.1",
			},
			want: +1,
		},
		{
			name: "redhat v1: module+el8, v2: module+el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v1:     "0.0.1-0.0.1.module+el8",
				v2:     "0.0.1-0.0.1.module+el8_10",
			},
			want: -1,
		},
		{
			name: "rpm version only v1: 0.0.1, v2: 0.0.1",
			rt:   affectedrangeTypes.RangeTypeRPMVersionOnly,
			args: args{
				v1: "0.0.1",
				v2: "0.0.1",
			},
			want: 0,
		},
		{
			name: "rpm version only v1: 1:0.0.1-1, v2: 0.0.2",
			rt:   affectedrangeTypes.RangeTypeRPMVersionOnly,
			args: args{
				v1: "1:0.0.1-1",
				v2: "0.0.2",
			},
			want: -1,
		},
		{
			name: "rpm version only v1: 1:0.0.2, v2: 0.0.1",
			rt:   affectedrangeTypes.RangeTypeRPMVersionOnly,
			args: args{
				v1: "1:0.0.2",
				v2: "0.0.1",
			},
			want: +1,
		},
		{
			name: "rpm version only v1: 1:0.0.1-1, v2: 0.0.1",
			rt:   affectedrangeTypes.RangeTypeRPMVersionOnly,
			args: args{
				v1: "1:0.0.1-1",
				v2: "0.0.1",
			},
			want: 0,
		}, {
			name: "unknown type",
			rt:   affectedrangeTypes.RangeTypeUnknown,
			args: args{
				v1: "awful-version",
				v2: "XXXX",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rt.Compare(tt.args.family, tt.args.v1, tt.args.v2)
			if (err != nil) != tt.wantErr {
				t.Errorf("RangeType.Compare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RangeType.Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
