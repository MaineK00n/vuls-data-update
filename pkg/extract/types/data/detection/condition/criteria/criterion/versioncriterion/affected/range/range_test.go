package affectedrange_test

import (
	"fmt"
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
		ecosystem ecosystemTypes.Ecosystem
		v1        string
		v2        string
	}
	tests := []struct {
		name    string
		rt      affectedrangeTypes.RangeType
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "alma v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "alma v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.module_el9",
			},
			wantErr: true,
		},
		{
			name: "alma v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, "9")),
				v1:        "0.0.1-0.0.1.module_el9",
				v2:        "0.0.1-0.0.1.module_el9",
			},
			want: 0,
		},
		{
			name: "rocky v1: rocky, v2: rocky",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "rocky v1: rocky sig cloud, v2: rocky",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, "9")),
				v1:        "0.0.1-0.0.1.el9.cloud.0",
				v2:        "0.0.1-0.0.1.el9",
			},
			wantErr: true,
		},
		{
			name: "rocky v1: rocky sig cloud, v2: rocky sig cloud",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, "9")),
				v1:        "0.0.1-0.0.1.el9.cloud.0",
				v2:        "0.0.1-0.0.1.el9.cloud.0.1",
			},
			want: -1,
		},
		{
			name: "rocky v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "rocky v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, "9")),
				v1:        "0.0.1-0.0.1.module+el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: not ksplice, v2: not ksplice",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: not ksplice, v2: ksplice1",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.ksplice1.el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: ksplice1, v2: ksplice1",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.ksplice1.el9",
				v2:        "0.0.1-0.0.1.ksplice1.el9",
			},
			want: 0,
		},
		{
			name: "oracle v1: ksplice1, v2: ksplice2",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.ksplice1.el9",
				v2:        "0.0.1-0.0.1.ksplice2.el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "oracle v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeOracle, "9")),
				v1:        "0.0.1-0.0.1.module+el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "fedora v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeFedora, "35")),
				v1:        "0.0.1-0.0.1.fc35",
				v2:        "0.0.1-0.0.1.fc35",
			},
			want: 0,
		},
		{
			name: "fedora v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeFedora, "35")),
				v1:        "0.0.1-0.0.1.fc35",
				v2:        "0.0.1-0.0.1.module_f35",
			},
			wantErr: true,
		},
		{
			name: "fedora v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeFedora, "35")),
				v1:        "0.0.1-0.0.1.module_f35",
				v2:        "0.0.1-0.0.1.module_f35",
			},
			want: 0,
		},
		{
			name: "redhat v1: non modular package, v2: non modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.el9",
			},
			want: 0,
		},
		{
			name: "redhat v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, "9")),
				v1:        "0.0.1-0.0.1.el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			wantErr: true,
		},
		{
			name: "redhat v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, "9")),
				v1:        "0.0.1-0.0.1.module+el9",
				v2:        "0.0.1-0.0.1.module+el9",
			},
			want: 0,
		},
		{
			name: "unknown type",
			rt:   affectedrangeTypes.RangeTypeUnknown,
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeCPE,
				v1:        "awful-version",
				v2:        "XXXX",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rt.Compare(tt.args.ecosystem, tt.args.v1, tt.args.v2)
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
