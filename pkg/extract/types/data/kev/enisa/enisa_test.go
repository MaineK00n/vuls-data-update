package enisa_test

import (
	"testing"
	"time"

	enisaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/enisa"
)

func TestSort(t *testing.T) {
	tests := []struct {
		name  string
		input enisaTypes.ENISA
		want  enisaTypes.ENISA
	}{
		{
			name: "sorts ExploitationTypes and ThreatActors",
			input: enisaTypes.ENISA{
				ExploitationTypes: []string{"ransomware", "APT"},
				ThreatActors:      []string{"UNC6586", "UNC1151"},
			},
			want: enisaTypes.ENISA{
				ExploitationTypes: []string{"APT", "ransomware"},
				ThreatActors:      []string{"UNC1151", "UNC6586"},
			},
		},
		{
			name:  "empty",
			input: enisaTypes.ENISA{OriginSource: "CNW"},
			want:  enisaTypes.ENISA{OriginSource: "CNW"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.Sort()
			if enisaTypes.Compare(tt.input, tt.want) != 0 {
				t.Errorf("Sort() result mismatch: got %+v, want %+v", tt.input, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x enisaTypes.ENISA
		y enisaTypes.ENISA
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: enisaTypes.ENISA{
					DateReported:      time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
					PatchedSince:      "tbc",
					OriginSource:      "cnw",
					ExploitationType:  "ransomware",
					ExploitationTypes: []string{"ransomware"},
					ThreatActors:      []string{"UNC6586"},
				},
				y: enisaTypes.ENISA{
					DateReported:      time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
					PatchedSince:      "tbc",
					OriginSource:      "cnw",
					ExploitationType:  "ransomware",
					ExploitationTypes: []string{"ransomware"},
					ThreatActors:      []string{"UNC6586"},
				},
			},
			want: 0,
		},
		{
			name: "x:dateReported < y:dateReported",
			args: args{
				x: enisaTypes.ENISA{DateReported: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)},
				y: enisaTypes.ENISA{DateReported: time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)},
			},
			want: -1,
		},
		{
			name: "x:exploitationType > y:exploitationType",
			args: args{
				x: enisaTypes.ENISA{ExploitationType: "ransomware"},
				y: enisaTypes.ENISA{ExploitationType: "apt"},
			},
			want: +1,
		},
		{
			name: "x:exploitationTypes < y:exploitationTypes",
			args: args{
				x: enisaTypes.ENISA{ExploitationTypes: []string{"APT"}},
				y: enisaTypes.ENISA{ExploitationTypes: []string{"APT", "ransomware"}},
			},
			want: -1,
		},
		{
			name: "x:threatActors > y:threatActors",
			args: args{
				x: enisaTypes.ENISA{ThreatActors: []string{"UNC6586"}},
				y: enisaTypes.ENISA{ThreatActors: []string{"UNC1151"}},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := enisaTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
