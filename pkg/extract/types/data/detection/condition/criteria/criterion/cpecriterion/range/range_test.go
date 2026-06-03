package cpecriterionrange_test

import (
	"testing"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestCompare(t *testing.T) {
	type args struct {
		x ccRangeTypes.Range
		y ccRangeTypes.Range
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "both empty",
			args: args{x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER}, y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER}},
			want: 0,
		},
		{
			name: "identical",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			want: 0,
		},
		{
			name: "ge smaller wins (lex)",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "2.0.0"},
			},
			want: -1,
		},
		{
			name: "ge larger wins (lex)",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "2.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			},
			want: +1,
		},
		{
			name: "ge equal, gt empty < gt non-empty",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", GreaterThan: "1.5.0"},
			},
			want: -1,
		},
		{
			name: "ge/gt equal, lt differs",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "3.0.0"},
			},
			want: -1,
		},
		{
			name: "ge/gt/le equal, lt differs (last field of cmp.Or chain)",
			args: args{
				x: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0", LessThan: "3.0.0"},
				y: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0", LessThan: "2.5.0"},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ccRangeTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRange_Accept(t *testing.T) {
	tests := []struct {
		name    string
		r       ccRangeTypes.Range
		v       string
		want    bool
		wantErr bool
	}{
		{
			name: "empty range matches anything",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER},
			v:    "1.0.0",
			want: true,
		},
		{
			name: "empty range matches even unparseable v",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER},
			v:    "not-a-semver",
			want: true,
		},
		{
			name: "ge inclusive lower, equal",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			v:    "1.0.0",
			want: true,
		},
		{
			name: "ge inclusive lower, below",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0"},
			v:    "0.9.9",
			want: false,
		},
		{
			name: "gt exclusive lower, equal rejected",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterThan: "1.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "gt exclusive lower, above",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterThan: "1.0.0"},
			v:    "1.0.1",
			want: true,
		},
		{
			name: "le inclusive upper, equal",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0"},
			v:    "2.0.0",
			want: true,
		},
		{
			name: "le inclusive upper, above",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessEqual: "2.0.0"},
			v:    "2.0.1",
			want: false,
		},
		{
			name: "lt exclusive upper, equal rejected",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "2.0.0",
			want: false,
		},
		{
			name: "lt exclusive upper, below",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "1.9.9",
			want: true,
		},
		{
			name: "ge+lt window, in",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "1.5.0",
			want: true,
		},
		{
			name: "ge+lt window, below",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "0.9.0",
			want: false,
		},
		{
			name: "ge+lt window, at upper bound",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			v:    "2.0.0",
			want: false,
		},
		{
			name: "unparseable v yields false, no error",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			v:    "not-a-semver",
			want: false,
		},
		{
			name: "Version (loose) accepts 4-segment",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeVersion, LessThan: "9.16.20.0"},
			v:    "9.16.19.0",
			want: true,
		},
		{
			name: "Version (loose) rejects above bound",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeVersion, LessThan: "9.16.20.0"},
			v:    "9.16.21.0",
			want: false,
		},
		{
			name: "Unknown type never matches",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeUnknown, LessThan: "2.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "unset type (zero) treated as unknown",
			r:    ccRangeTypes.Range{LessThan: "2.0.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name:    "unparseable bound surfaces error",
			r:       ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "not-a-semver"},
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
