package epss_test

import (
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/epss"
)

func TestCompare(t *testing.T) {
	type args struct {
		x epss.EPSS
		y epss.EPSS
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: epss.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
				y: epss.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
			},
			want: 0,
		},
		{
			name: "x:model < y:model",
			args: args{
				x: epss.EPSS{
					Model: "v2022.01.01",
				},
				y: epss.EPSS{
					Model: "v2023.03.01",
				},
			},
			want: -1,
		},
		{
			name: "x:score_date > y:score_date",
			args: args{
				x: epss.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC),
				},
				y: epss.EPSS{
					Model:     "v2023.03.01",
					ScoreDate: time.Date(2023, time.March, 6, 0, 0, 0, 0, time.UTC),
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := epss.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
