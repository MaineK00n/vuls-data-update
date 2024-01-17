package version

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
)

func TestContains(t *testing.T) {
	type args struct {
		a detection.Affected
		v string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "0.0.0 [= 0.0.1]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							Equal: "0.0.1",
						}},
				},
				v: "0.0.0",
			},
			want: false,
		},
		{
			name: "0.0.1, [= 0.0.1]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							Equal: "0.0.1",
						}},
				},
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [>0.0.0]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							GreaterThan: "0.0.0",
						}},
				},
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [>0.0.0, <0.0.2]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							LessThan:    "0.0.2",
							GreaterThan: "0.0.0",
						}},
				},
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [<0.0.2]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							LessThan: "0.0.2",
						}},
				},
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.3 [>0.0.0, <0.0.2]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							LessThan:    "0.0.2",
							GreaterThan: "0.0.0",
						}},
				},
				v: "0.0.3",
			},
			want: false,
		},
		{
			name: "0.0.0 [>=0.0.0]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							GreaterEqual: "0.0.0",
						}},
				},
				v: "0.0.0",
			},
			want: true,
		},
		{
			name: "0.0.0 [<=0.0.0]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							LessEqual: "0.0.0",
						}},
				},
				v: "0.0.0",
			},
			want: true,
		},
		{
			name: "0.0.0 [>=0.0.0, <=0.0.0]",
			args: args{
				a: detection.Affected{
					Type: detection.RangeTypeSEMVER,
					Range: []detection.Range{
						{
							LessEqual:    "0.0.0",
							GreaterEqual: "0.0.0",
						}},
				},
				v: "0.0.0",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.args.a, tt.args.v); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}
