package ssvc_test

import (
	"testing"

	ssvcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/ssvc"
)

func TestCompare(t *testing.T) {
	type args struct {
		x ssvcTypes.SSVC
		y ssvcTypes.SSVC
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: ssvcTypes.SSVC{
					Source:  "CISA-ADP",
					Role:    "CISA Coordinator",
					Version: "2.0.3",
					Options: []ssvcTypes.Option{{Key: "Exploitation", Value: "none"}},
				},
				y: ssvcTypes.SSVC{
					Source:  "CISA-ADP",
					Role:    "CISA Coordinator",
					Version: "2.0.3",
					Options: []ssvcTypes.Option{{Key: "Exploitation", Value: "none"}},
				},
			},
			want: 0,
		},
		{
			name: "x:source < y:source",
			args: args{
				x: ssvcTypes.SSVC{Source: "CISA-ADP"},
				y: ssvcTypes.SSVC{Source: "mitre"},
			},
			want: -1,
		},
		{
			name: "x:option value > y:option value",
			args: args{
				x: ssvcTypes.SSVC{
					Source:  "CISA-ADP",
					Options: []ssvcTypes.Option{{Key: "Exploitation", Value: "poc"}},
				},
				y: ssvcTypes.SSVC{
					Source:  "CISA-ADP",
					Options: []ssvcTypes.Option{{Key: "Exploitation", Value: "none"}},
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ssvcTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
