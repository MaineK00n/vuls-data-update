package v31

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    *CVSSv31
		wantErr bool
	}{
		{
			name: "base",
			args: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H",
			want: &CVSSv31{
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
			want: &CVSSv31{
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
			want: &CVSSv31{
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
			got, err := Parse(tt.args)
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
