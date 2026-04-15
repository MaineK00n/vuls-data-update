package enisa_test

import (
	"testing"
	"time"

	enisaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/enisa"
)

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
					DateReported:     time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
					PatchedSince:     "tbc",
					OriginSource:     "cnw",
					ExploitationType: "ransomware",
				},
				y: enisaTypes.ENISA{
					DateReported:     time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
					PatchedSince:     "tbc",
					OriginSource:     "cnw",
					ExploitationType: "ransomware",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := enisaTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
