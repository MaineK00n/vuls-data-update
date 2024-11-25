package v2_test

import (
	"reflect"
	"testing"

	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    *v2Types.CVSSv2
		wantErr bool
	}{
		{
			name: "base",
			args: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			want: &v2Types.CVSSv2{
				Vector:                   "AV:N/AC:L/Au:N/C:C/I:C/A:C",
				BaseScore:                10.0,
				NVDBaseSeverity:          "HIGH",
				TemporalScore:            10.0,
				NVDTemporalSeverity:      "HIGH",
				EnvironmentalScore:       10.0,
				NVDEnvironmentalSeverity: "HIGH",
			},
		},
		{
			name: "base + temporal",
			args: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
			want: &v2Types.CVSSv2{
				Vector:                   "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
				BaseScore:                10.0,
				NVDBaseSeverity:          "HIGH",
				TemporalScore:            7.8,
				NVDTemporalSeverity:      "HIGH",
				EnvironmentalScore:       7.8,
				NVDEnvironmentalSeverity: "HIGH",
			},
		},
		{
			name: "base + temporal + environmental",
			args: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:MH/TD:M/CR:M/IR:L/AR:L",
			want: &v2Types.CVSSv2{
				Vector:                   "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:MH/TD:M/CR:M/IR:L/AR:L",
				BaseScore:                10.0,
				NVDBaseSeverity:          "HIGH",
				TemporalScore:            7.8,
				NVDTemporalSeverity:      "HIGH",
				EnvironmentalScore:       6.2,
				NVDEnvironmentalSeverity: "MEDIUM",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v2Types.Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x v2Types.CVSSv2
		y v2Types.CVSSv2
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
			if got := v2Types.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
