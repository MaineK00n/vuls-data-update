package epss_test

import (
	"testing"
	"time"

	epssTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/epss"
)

func TestCompare(t *testing.T) {
	type args struct {
		x epssTypes.EPSS
		y epssTypes.EPSS
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: epssTypes.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
				y: epssTypes.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
			},
			want: 0,
		},
		{
			name: "x:model < y:model",
			args: args{
				x: epssTypes.EPSS{
					Model: "v2022.01.01",
				},
				y: epssTypes.EPSS{
					Model: "v2023.03.01",
				},
			},
			want: -1,
		},
		{
			name: "x:score_date > y:score_date",
			args: args{
				x: epssTypes.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
				y: epssTypes.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 6, 0, 0, 0, 0, time.UTC),
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := epssTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
