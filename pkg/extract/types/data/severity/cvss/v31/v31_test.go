package v31_test

import (
	"reflect"
	"testing"

	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    *v31Types.CVSSv31
		wantErr bool
	}{
		{
			name: "base",
			args: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H",
			want: &v31Types.CVSSv31{
				Vector:                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H",
				BaseScore:             9.9,
				BaseSeverity:          "CRITICAL",
				TemporalScore:         9.9,
				TemporalSeverity:      "CRITICAL",
				EnvironmentalScore:    9.9,
				EnvironmentalSeverity: "CRITICAL",
			},
		},
		{
			name: "base + temporal",
			args: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:O/RC:C",
			want: &v31Types.CVSSv31{
				Vector:                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:O/RC:C",
				BaseScore:             9.9,
				BaseSeverity:          "CRITICAL",
				TemporalScore:         8.9,
				TemporalSeverity:      "HIGH",
				EnvironmentalScore:    8.9,
				EnvironmentalSeverity: "HIGH",
			},
		},
		{
			name: "base + temporal + environmental",
			args: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:L/MA:L",
			want: &v31Types.CVSSv31{
				Vector:                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H/E:P/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MC:L/MI:L/MA:L",
				BaseScore:             9.9,
				BaseSeverity:          "CRITICAL",
				TemporalScore:         8.9,
				TemporalSeverity:      "HIGH",
				EnvironmentalScore:    3.3,
				EnvironmentalSeverity: "LOW",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v31Types.Parse(tt.args)
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
		x v31Types.CVSSv31
		y v31Types.CVSSv31
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
			if got := v31Types.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
