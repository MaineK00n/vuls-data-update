package severity_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
)

func TestCompare(t *testing.T) {
	type args struct {
		x severity.Severity
		y severity.Severity
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: severity.Severity{
					Type:   severity.SeverityTypeVendor,
					Source: "source1",
				},
				y: severity.Severity{
					Type:   severity.SeverityTypeVendor,
					Source: "source1",
				},
			},
			want: 0,
		},
		{
			name: "x:source < y:source",
			args: args{
				x: severity.Severity{
					Type:   severity.SeverityTypeVendor,
					Source: "source1",
				},
				y: severity.Severity{
					Type:   severity.SeverityTypeVendor,
					Source: "source2",
				},
			},
			want: -1,
		},
		{
			name: "x:type > y:type",
			args: args{
				x: severity.Severity{
					Type:   severity.SeverityTypeCVSSv31,
					Source: "source1",
				},
				y: severity.Severity{
					Type:   severity.SeverityTypeVendor,
					Source: "source1",
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := severity.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
