package cpecriterionrange_test

import (
	"testing"

	cpecRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestCompare(t *testing.T) {
	type args struct {
		x cpecRangeTypes.Range
		y cpecRangeTypes.Range
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "both empty",
			args: args{x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER}, y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER}},
			want: 0,
		},
		{
			name: "identical",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			want: 0,
		},
		{
			name: "ge smaller wins (lex)",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "2.0.0"},
			},
			want: -1,
		},
		{
			name: "ge larger wins (lex)",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "2.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			},
			want: +1,
		},
		{
			name: "ge equal, gt empty < gt non-empty",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", GreaterThan: "1.5.0"},
			},
			want: -1,
		},
		{
			name: "ge/gt equal, lt differs",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "3.0.0"},
			},
			want: -1,
		},
		{
			name: "ge/gt/le equal, lt differs (last field of cmp.Or chain)",
			args: args{
				x: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0", LessThan: "3.0.0"},
				y: cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0", LessThan: "2.5.0"},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cpecRangeTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRange_Accept(t *testing.T) {
	tests := []struct {
		name    string
		r       cpecRangeTypes.Range
		v       string
		want    bool
		wantErr bool
	}{
		{
			name: "empty range matches anything",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER},
			v:    "1.0.0",
			want: true,
		},
		{
			name: "empty range matches even unparseable v",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER},
			v:    "not-a-semver",
			want: true,
		},
		{
			name: "ge inclusive lower, equal",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			v:    "1.0.0",
			want: true,
		},
		{
			name: "ge inclusive lower, below",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			v:    "0.9.9",
			want: false,
		},
		{
			name: "gt exclusive lower, equal rejected",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterThan: "1.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "gt exclusive lower, above",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterThan: "1.0.0"},
			v:    "1.0.1",
			want: true,
		},
		{
			name: "le inclusive upper, equal",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0"},
			v:    "2.0.0",
			want: true,
		},
		{
			name: "le inclusive upper, above",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0"},
			v:    "2.0.1",
			want: false,
		},
		{
			name: "lt exclusive upper, equal rejected",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "2.0.0",
			want: false,
		},
		{
			name: "lt exclusive upper, below",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "1.9.9",
			want: true,
		},
		{
			name: "ge+lt window, in",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "1.5.0",
			want: true,
		},
		{
			name: "ge+lt window, below",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "0.9.0",
			want: false,
		},
		{
			name: "ge+lt window, at upper bound",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "2.0.0",
			want: false,
		},
		{
			name: "unparseable v yields false, no error",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "not-a-semver",
			want: false,
		},
		{
			name: "Version (loose) accepts 4-segment",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeVersion, LessThan: "9.16.20.0"},
			v:    "9.16.19.0",
			want: true,
		},
		{
			name: "Version (loose) rejects above bound",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeVersion, LessThan: "9.16.20.0"},
			v:    "9.16.21.0",
			want: false,
		},
		{
			name: "Unknown type never matches",
			r:    cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeUnknown, LessThan: "2.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "unset type (zero) treated as unknown",
			r:    cpecRangeTypes.Range{LessThan: "2.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name:    "unparseable bound surfaces error",
			r:       cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "not-a-semver"},
			v:       "1.0.0",
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.r.Accept(tt.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
