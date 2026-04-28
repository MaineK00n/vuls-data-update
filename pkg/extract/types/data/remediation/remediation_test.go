package remediation_test

import (
	"testing"

	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
)

func TestCompare(t *testing.T) {
	type args struct {
		x remediationTypes.Remediation
		y remediationTypes.Remediation
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: remediationTypes.Remediation{
					Source:      "source1",
					Description: "description1",
				},
				y: remediationTypes.Remediation{
					Source:      "source1",
					Description: "description1",
				},
			},
			want: 0,
		},
		{
			name: "x:source < y:source",
			args: args{
				x: remediationTypes.Remediation{
					Source:      "source1",
					Description: "description",
				},
				y: remediationTypes.Remediation{
					Source:      "source2",
					Description: "description",
				},
			},
			want: -1,
		},
		{
			name: "x:description > y:description",
			args: args{
				x: remediationTypes.Remediation{
					Source:      "source",
					Description: "description2",
				},
				y: remediationTypes.Remediation{
					Source:      "source",
					Description: "description1",
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := remediationTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
