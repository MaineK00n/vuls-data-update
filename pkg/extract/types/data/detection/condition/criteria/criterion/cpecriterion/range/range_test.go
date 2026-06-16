package cpecriterionrange_test

import (
	stderrors "errors"
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
			name: "unparseable bound is swallowed as graceful non-match (CompareError classified)",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "not-a-semver"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "empty range with Type=Unknown returns false",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeUnknown},
			v:    "1.0.0",
			want: false,
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

func TestRangeType_Compare(t *testing.T) {
	tests := []struct {
		name           string
		t              ccRangeTypes.RangeType
		v1, v2         string
		want           int
		wantCompareErr bool // expect *CompareError-wrapped failure (parse / unknown type)
		wantOtherErr   bool // expect a non-CompareError (e.g. unsupported type)
	}{
		{name: "semver: v1 < v2", t: ccRangeTypes.RangeTypeSEMVER, v1: "1.0.0", v2: "2.0.0", want: -1},
		{name: "semver: equal", t: ccRangeTypes.RangeTypeSEMVER, v1: "1.0.0", v2: "1.0.0", want: 0},
		{name: "semver: v1 > v2", t: ccRangeTypes.RangeTypeSEMVER, v1: "2.0.0", v2: "1.0.0", want: 1},
		{name: "semver: v1 unparseable → CompareError", t: ccRangeTypes.RangeTypeSEMVER, v1: "not-a-semver", v2: "1.0.0", wantCompareErr: true},
		{name: "semver: v2 unparseable → CompareError", t: ccRangeTypes.RangeTypeSEMVER, v1: "1.0.0", v2: "not-a-semver", wantCompareErr: true},
		{name: "fortinet: v1 < v2 (semver comparator)", t: ccRangeTypes.RangeTypeFortinet, v1: "7.0.0", v2: "7.0.1", want: -1},
		{name: "fortinet: equal", t: ccRangeTypes.RangeTypeFortinet, v1: "7.2.0", v2: "7.2.0", want: 0},
		{name: "fortinet: v1 > v2", t: ccRangeTypes.RangeTypeFortinet, v1: "7.1.0", v2: "7.0.0", want: 1},
		{name: "fortinet: v1 unparseable → CompareError", t: ccRangeTypes.RangeTypeFortinet, v1: "not-a-version", v2: "7.0.0", wantCompareErr: true},
		{name: "version (loose): 4-segment v1 < v2", t: ccRangeTypes.RangeTypeVersion, v1: "9.16.19.0", v2: "9.16.20.0", want: -1},
		{name: "version (loose): v1 unparseable → CompareError", t: ccRangeTypes.RangeTypeVersion, v1: "x.y.z.w.q", v2: "1.0", wantCompareErr: true},
		{name: "Unknown → CompareError wrapping ErrRangeTypeUnknown", t: ccRangeTypes.RangeTypeUnknown, v1: "1.0.0", v2: "2.0.0", wantCompareErr: true},
		{name: "unset (zero) RangeType collapses to Unknown → CompareError", t: ccRangeTypes.RangeType(0), v1: "1.0.0", v2: "2.0.0", wantCompareErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.t.Compare(tt.v1, tt.v2)
			isCompareErr := false
			if err != nil {
				_, isCompareErr = stderrors.AsType[*ccRangeTypes.CompareError](err)
			}
			switch {
			case tt.wantCompareErr && !isCompareErr:
				t.Errorf("Compare() error = %v, want *CompareError", err)
			case tt.wantOtherErr && (err == nil || isCompareErr):
				t.Errorf("Compare() error = %v, want non-CompareError", err)
			case !tt.wantCompareErr && !tt.wantOtherErr && err != nil:
				t.Errorf("Compare() unexpected error: %v", err)
			case err == nil && got != tt.want:
				t.Errorf("Compare() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestErrRangeTypeUnknown_Wrapped(t *testing.T) {
	_, err := ccRangeTypes.RangeTypeUnknown.Compare("1.0.0", "2.0.0")
	if err == nil {
		t.Fatal("expected error")
	}
	if !stderrors.Is(err, ccRangeTypes.ErrRangeTypeUnknown) {
		t.Errorf("expected ErrRangeTypeUnknown via errors.Is; got %v", err)
	}
}
