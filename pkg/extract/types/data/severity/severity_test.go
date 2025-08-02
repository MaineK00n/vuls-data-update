package severity_test

import (
	"testing"

	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
)

func TestCompare(t *testing.T) {
	type args struct {
		x severityTypes.Severity
		y severityTypes.Severity
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
				},
				y: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
				},
			},
			want: 0,
		},
		{
			name: "x:source < y:source",
			args: args{
				x: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
				},
				y: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source2",
				},
			},
			want: -1,
		},
		{
			name: "x:type > y:type",
			args: args{
				x: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeCVSSv31,
					Source: "source1",
				},
				y: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
				},
			},
			want: +1,
		},
		{
			name: "x:vendor < y:vendor",
			args: args{
				x: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
					Vendor: func() *string { s := "low"; return &s }(),
				},
				y: severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "source1",
					Vendor: func() *string { s := "medium"; return &s }(),
				},
			},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := severityTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
