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
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.el8",
			},
			want: 0,
		},
		{
			name: "centos v1: centos package, v2: non centos package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.el8.centos",
				v2:     "0.0.1-0.0.1.el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: non modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.module_el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: modular package, v2: modular package",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.module_el8",
				v2:     "0.0.1-0.0.1.module_el8",
			},
			want: 0,
		},
		{
			name: "centos v1: el7, v2: el8",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.el7",
				v2:     "0.0.1-0.0.1.el8",
			},
			wantErr: true,
		},
		{
			name: "centos v1: el8, v2: el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
				v1:     "0.0.1-0.0.1.el8",
				v2:     "0.0.1-0.0.1.el8_10",
			},
			want: -1,
		},
		{
			name: "centos v1: module+el8, v2: module+el8_10",
			rt:   affectedrangeTypes.RangeTypeRPM,
			args: args{
				family: ecosystemTypes.EcosystemTypeCentOS,
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
		},
		{
			name: "microsoft-defender-android v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderAndroid,
			args: args{
				v1: "1.0.3011.302",
				v2: "1.0.3011.302",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-android v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderAndroid,
			args: args{
				v1: "1.0.3011.302",
				v2: "1.0.7001.101",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-android v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderAndroid,
			args: args{
				v1: "1.0.7128.101",
				v2: "1.0.3011.302",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-android invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderAndroid,
			args: args{
				v1: "invalid",
				v2: "1.0.3011.302",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-ios v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIOS,
			args: args{
				v1: "1.1.18090109",
				v2: "1.1.18090109",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-ios v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIOS,
			args: args{
				v1: "1.1.18090109",
				v2: "1.1.58140101",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-ios v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIOS,
			args: args{
				v1: "1.1.58140101",
				v2: "1.1.18090109",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-ios invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIOS,
			args: args{
				v1: "invalid",
				v2: "1.1.18090109",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-iot v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIoT,
			args: args{
				v1: "10.5.2",
				v2: "10.5.2",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-iot v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIoT,
			args: args{
				v1: "10.5.2",
				v2: "22.1.2",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-iot v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIoT,
			args: args{
				v1: "22.2.6",
				v2: "10.5.2",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-iot invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderIoT,
			args: args{
				v1: "10.5.2.0",
				v2: "10.5.2",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-linux v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderLinux,
			args: args{
				v1: "101.24052.2",
				v2: "101.24052.2",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-linux v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderLinux,
			args: args{
				v1: "101.24052.2",
				v2: "101.25022.2",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-linux v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderLinux,
			args: args{
				v1: "101.25032.10",
				v2: "101.24052.2",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-linux invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderLinux,
			args: args{
				v1: "invalid",
				v2: "101.24052.2",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-mac v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderMac,
			args: args{
				v1: "101.60.91",
				v2: "101.60.91",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-mac v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderMac,
			args: args{
				v1: "101.60.91",
				v2: "101.78.13",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-mac v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderMac,
			args: args{
				v1: "101.78.13",
				v2: "101.60.91",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-mac invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderMac,
			args: args{
				v1: "invalid",
				v2: "101.60.91",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-security-intelligence v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderSecurityIntelligence,
			args: args{
				v1: "1.379.200.0",
				v2: "1.379.200.0",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-security-intelligence v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderSecurityIntelligence,
			args: args{
				v1: "1.379.200.0",
				v2: "1.391.1332.0",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-security-intelligence v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderSecurityIntelligence,
			args: args{
				v1: "1.391.1332.0",
				v2: "1.379.200.0",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-security-intelligence invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderSecurityIntelligence,
			args: args{
				v1: "invalid",
				v2: "1.379.200.0",
			},
			wantErr: true,
		},
		{
			name: "microsoft-defender-windows v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderWindows,
			args: args{
				v1: "4.18.23100.2009",
				v2: "4.18.23100.2009",
			},
			want: 0,
		},
		{
			name: "microsoft-defender-windows v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderWindows,
			args: args{
				v1: "1.1.23060.3001",
				v2: "4.18.23100.2009",
			},
			want: -1,
		},
		{
			name: "microsoft-defender-windows v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderWindows,
			args: args{
				v1: "4.18.24010.12",
				v2: "4.18.23100.2009",
			},
			want: +1,
		},
		{
			name: "microsoft-defender-windows invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDefenderWindows,
			args: args{
				v1: "invalid",
				v2: "4.18.23100.2009",
			},
			wantErr: true,
		},
		{
			name: "microsoft-dotnet-core v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDotNetCore,
			args: args{
				v1: "8.0.2",
				v2: "8.0.2",
			},
			want: 0,
		},
		{
			name: "microsoft-dotnet-core v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDotNetCore,
			args: args{
				v1: "8.0.2",
				v2: "9.0.13",
			},
			want: -1,
		},
		{
			name: "microsoft-dotnet-core v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDotNetCore,
			args: args{
				v1: "9.0.13",
				v2: "8.0.2",
			},
			want: +1,
		},
		{
			name: "microsoft-dotnet-core invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftDotNetCore,
			args: args{
				v1: "8.0.abc",
				v2: "8.0.2",
			},
			wantErr: true,
		},
		{
			name: "microsoft-edge v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftEdge,
			args: args{
				v1: "88.0.705.18",
				v2: "88.0.705.18",
			},
			want: 0,
		},
		{
			name: "microsoft-edge v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftEdge,
			args: args{
				v1: "20.10240",
				v2: "88.0.705.18",
			},
			want: -1,
		},
		{
			name: "microsoft-edge v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftEdge,
			args: args{
				v1: "88.0.705.18",
				v2: "20.10240",
			},
			want: +1,
		},
		{
			name: "microsoft-edge invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftEdge,
			args: args{
				v1: "1.2.3",
				v2: "88.0.705.18",
			},
			wantErr: true,
		},
		{
			name: "microsoft-exchange v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftExchange,
			args: args{
				v1: "15.1.2375.12",
				v2: "15.1.2375.12",
			},
			want: 0,
		},
		{
			name: "microsoft-exchange v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftExchange,
			args: args{
				v1: "15.0.1497.48",
				v2: "15.1.2375.12",
			},
			want: -1,
		},
		{
			name: "microsoft-exchange v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftExchange,
			args: args{
				v1: "15.2.1544.9",
				v2: "15.1.2375.12",
			},
			want: +1,
		},
		{
			name: "microsoft-exchange invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftExchange,
			args: args{
				v1: "15.0.abc.48",
				v2: "15.1.2375.12",
			},
			wantErr: true,
		},
		{
			name: "microsoft-office-mac v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeMac,
			args: args{
				v1: "16.100.25081015",
				v2: "16.100.25081015",
			},
			want: 0,
		},
		{
			name: "microsoft-office-mac v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeMac,
			args: args{
				v1: "16.54.21101001",
				v2: "16.100.25081015",
			},
			want: -1,
		},
		{
			name: "microsoft-office-mac v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeMac,
			args: args{
				v1: "16.100.25081015",
				v2: "16.54.21101001",
			},
			want: +1,
		},
		{
			name: "microsoft-office-mac invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeMac,
			args: args{
				v1: "16.50.abc",
				v2: "16.100.25081015",
			},
			wantErr: true,
		},
		{
			name: "microsoft-office-windows v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeWindows,
			args: args{
				v1: "16.0.5474.1001",
				v2: "16.0.5474.1001",
			},
			want: 0,
		},
		{
			name: "microsoft-office-windows v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeWindows,
			args: args{
				v1: "15.0.5589.1002",
				v2: "16.0.5474.1001",
			},
			want: -1,
		},
		{
			name: "microsoft-office-windows v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeWindows,
			args: args{
				v1: "16.0.5474.1001",
				v2: "15.0.5589.1002",
			},
			want: +1,
		},
		{
			name: "microsoft-office-windows invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftOfficeWindows,
			args: args{
				v1: "16.0.xxxx.1000",
				v2: "16.0.5474.1001",
			},
			wantErr: true,
		},
		{
			name: "microsoft-sharepoint v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSharePoint,
			args: args{
				v1: "16.0.5161.1000",
				v2: "16.0.5161.1000",
			},
			want: 0,
		},
		{
			name: "microsoft-sharepoint v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSharePoint,
			args: args{
				v1: "15.0.5353.1000",
				v2: "16.0.5161.1000",
			},
			want: -1,
		},
		{
			name: "microsoft-sharepoint v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSharePoint,
			args: args{
				v1: "16.0.18429.20162",
				v2: "16.0.5161.1000",
			},
			want: +1,
		},
		{
			name: "microsoft-sharepoint invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSharePoint,
			args: args{
				v1: "16.0.xxxx.1000",
				v2: "16.0.5161.1000",
			},
			wantErr: true,
		},
		{
			name: "microsoft-sqlserver v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSQLServer,
			args: args{
				v1: "15.0.2095.3",
				v2: "15.0.2095.3",
			},
			want: 0,
		},
		{
			name: "microsoft-sqlserver v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSQLServer,
			args: args{
				v1: "14.0.3465.1",
				v2: "15.0.2095.3",
			},
			want: -1,
		},
		{
			name: "microsoft-sqlserver v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSQLServer,
			args: args{
				v1: "16.0.4185.3",
				v2: "15.0.2095.3",
			},
			want: +1,
		},
		{
			name: "microsoft-sqlserver invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftSQLServer,
			args: args{
				v1: "15.0.abc.3",
				v2: "15.0.2095.3",
			},
			wantErr: true,
		},
		{
			name: "microsoft-teams-android v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsAndroid,
			args: args{
				v1: "1.0.0.2024022302",
				v2: "1.0.0.2024022302",
			},
			want: 0,
		},
		{
			name: "microsoft-teams-android v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsAndroid,
			args: args{
				v1: "1.0.0.2023070204",
				v2: "1.0.0.2024022302",
			},
			want: -1,
		},
		{
			name: "microsoft-teams-android v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsAndroid,
			args: args{
				v1: "1.0.0.2025112902",
				v2: "1.0.0.2024022302",
			},
			want: +1,
		},
		{
			name: "microsoft-teams-android invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsAndroid,
			args: args{
				v1: "invalid",
				v2: "1.0.0.2024022302",
			},
			wantErr: true,
		},
		{
			name: "microsoft-teams-client v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsClient,
			args: args{
				v1: "2.10.1",
				v2: "2.10.1",
			},
			want: 0,
		},
		{
			name: "microsoft-teams-client v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsClient,
			args: args{
				v1: "2.10.1",
				v2: "3.0.0",
			},
			want: -1,
		},
		{
			name: "microsoft-teams-client v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsClient,
			args: args{
				v1: "3.0.0",
				v2: "2.10.1",
			},
			want: +1,
		},
		{
			name: "microsoft-teams-client invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsClient,
			args: args{
				v1: "invalid",
				v2: "2.10.1",
			},
			wantErr: true,
		},
		{
			name: "microsoft-teams-desktop v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsDesktop,
			args: args{
				v1: "1.6.00.18681",
				v2: "1.6.00.18681",
			},
			want: 0,
		},
		{
			name: "microsoft-teams-desktop v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsDesktop,
			args: args{
				v1: "1.6.00.18681",
				v2: "25122.1415.3698.6812",
			},
			want: -1,
		},
		{
			name: "microsoft-teams-desktop v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsDesktop,
			args: args{
				v1: "25122.1415.3698.6812",
				v2: "1.6.00.18681",
			},
			want: +1,
		},
		{
			name: "microsoft-teams-desktop invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsDesktop,
			args: args{
				v1: "invalid",
				v2: "1.6.00.18681",
			},
			wantErr: true,
		},
		{
			name: "microsoft-teams-ios v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsIOS,
			args: args{
				v1: "2.5.0",
				v2: "2.5.0",
			},
			want: 0,
		},
		{
			name: "microsoft-teams-ios v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsIOS,
			args: args{
				v1: "2.5.0",
				v2: "5.12.1",
			},
			want: -1,
		},
		{
			name: "microsoft-teams-ios v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsIOS,
			args: args{
				v1: "8.3.1",
				v2: "2.5.0",
			},
			want: +1,
		},
		{
			name: "microsoft-teams-ios invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsIOS,
			args: args{
				v1: "invalid",
				v2: "2.5.0",
			},
			wantErr: true,
		},
		{
			name: "microsoft-teams-mac v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsMac,
			args: args{
				v1: "1.6.00.17554",
				v2: "1.6.00.17554",
			},
			want: 0,
		},
		{
			name: "microsoft-teams-mac v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsMac,
			args: args{
				v1: "1.6.00.17554",
				v2: "1.6.00.27656",
			},
			want: -1,
		},
		{
			name: "microsoft-teams-mac v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsMac,
			args: args{
				v1: "1.6.00.27656",
				v2: "1.6.00.17554",
			},
			want: +1,
		},
		{
			name: "microsoft-teams-mac invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftTeamsMac,
			args: args{
				v1: "invalid",
				v2: "1.6.00.17554",
			},
			wantErr: true,
		},

		{
			name: "microsoft-visualstudio v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVisualStudio,
			args: args{
				v1: "17.8.6",
				v2: "17.8.6",
			},
			want: 0,
		},
		{
			name: "microsoft-visualstudio v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVisualStudio,
			args: args{
				v1: "16.11.41",
				v2: "17.8.6",
			},
			want: -1,
		},
		{
			name: "microsoft-visualstudio v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVisualStudio,
			args: args{
				v1: "17.8.6",
				v2: "15.9.38",
			},
			want: +1,
		},
		{
			name: "microsoft-visualstudio invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVisualStudio,
			args: args{
				v1: "17.8",
				v2: "17.8.6",
			},
			wantErr: true,
		},
		{
			name: "microsoft-vscode v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVSCode,
			args: args{
				v1: "1.100.1",
				v2: "1.100.1",
			},
			want: 0,
		},
		{
			name: "microsoft-vscode v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVSCode,
			args: args{
				v1: "1.56.0",
				v2: "1.100.1",
			},
			want: -1,
		},
		{
			name: "microsoft-vscode v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVSCode,
			args: args{
				v1: "1.104.0",
				v2: "1.100.1",
			},
			want: +1,
		},
		{
			name: "microsoft-vscode invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftVSCode,
			args: args{
				v1: "1.abc.0",
				v2: "1.100.1",
			},
			wantErr: true,
		},
		{
			name: "microsoft-windows v1 == v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftWindows,
			args: args{
				v1: "10.0.19045.7058",
				v2: "10.0.19045.7058",
			},
			want: 0,
		},
		{
			name: "microsoft-windows v1 < v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftWindows,
			args: args{
				v1: "6.1.7601",
				v2: "10.0.19045.7058",
			},
			want: -1,
		},
		{
			name: "microsoft-windows v1 > v2",
			rt:   affectedrangeTypes.RangeTypeMicrosoftWindows,
			args: args{
				v1: "10.0.26100.8037",
				v2: "10.0.19045.7058",
			},
			want: +1,
		},
		{
			name: "microsoft-windows invalid version",
			rt:   affectedrangeTypes.RangeTypeMicrosoftWindows,
			args: args{
				v1: "10.0",
				v2: "10.0.19045.7058",
			},
			wantErr: true,
		},
		{
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
