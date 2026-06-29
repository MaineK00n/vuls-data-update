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
			name: "PAN-OS hotfix above base accepted within window",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "11.2.0", LessThan: "11.2.4-h1"},
			v:    "11.2.4",
			want: true,
		},
		{
			name: "PAN-OS hotfix at upper bound rejected",
			r:    ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "11.2.0", LessThan: "11.2.4-h1"},
			v:    "11.2.4-h1",
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
		{name: "fortinet: v1 < v2", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.0.0", v2: "7.0.1", want: -1},
		{name: "fortinet: equal", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2.0", v2: "7.2.0", want: 0},
		{name: "fortinet: v1 > v2", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.1.0", v2: "7.0.0", want: 1},
		{name: "fortinet: v1 unparseable → CompareError", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "not-a-version", v2: "7.0.0", wantCompareErr: true},
		// Train-style tokens (as produced by product.TrainRange) must compare,
		// both against each other and against fully-qualified semver bounds.
		{name: "fortinet: train minor < train minor", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2", v2: "7.4", want: -1},
		{name: "fortinet: train major < train major", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7", v2: "8", want: -1},
		{name: "fortinet: train equal", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2", v2: "7.2", want: 0},
		{name: "fortinet: concrete within train lower bound (7.2.0 >= 7.2)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2.0", v2: "7.2", want: 0},
		{name: "fortinet: concrete below next train (7.2.5 < 7.3)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2.5", v2: "7.3", want: -1},
		// Calendar versions (FortiSASE) and build suffixes are not semver. The
		// numeric prefix decides first; an equal prefix is broken by the suffix,
		// so a lettered build sorts just after its bare train and letters order
		// sequentially — while staying inside the train range.
		{name: "fortinet: bare train below its calendar build (25.2 < 25.2.a)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.2", v2: "25.2.a", want: -1},
		{name: "fortinet: calendar above its bare train (25.2.a > 25.2)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.2.a", v2: "25.2", want: 1},
		{name: "fortinet: calendar below next train (25.2.a < 25.3)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.2.a", v2: "25.3", want: -1},
		{name: "fortinet: calendar above prev train (25.2.a > 25.1)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.2.a", v2: "25.1", want: 1},
		{name: "fortinet: sequential letters (25.2.a < 25.2.b)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.2.a", v2: "25.2.b", want: -1},
		{name: "fortinet: letter patch after letter (25.1.a < 25.1.a.2)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.1.a", v2: "25.1.a.2", want: -1},
		{name: "fortinet: numeric letter-patch ordering (25.1.a.2 < 25.1.a.10)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.1.a.2", v2: "25.1.a.10", want: -1},
		{name: "fortinet: nested calendar above bare train (25.1.a.2 > 25.1)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "25.1.a.2", v2: "25.1", want: 1},
		{name: "fortinet: pure-numeric trailing zero stays equal (7.2.0 == 7.2)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2.0", v2: "7.2", want: 0},
		// A numeric build vs an alphabetic milestone at the same position is
		// undefined across Fortinet's two schemes → incomparable (swallowed).
		{name: "fortinet: numeric build vs calendar milestone → CompareError (1.2.1 vs 1.2.a)", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "1.2.1", v2: "1.2.a", wantCompareErr: true},
		{name: "fortinet: build suffix vs train → CompareError (7.1-b5955 vs 7.1)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.1-b5955", v2: "7.1", wantCompareErr: true},
		{name: "fortinet: non-version vs numeric → CompareError", t: ccRangeTypes.RangeTypeFortinetFortisase, v1: "alpha", v2: "25.2", wantCompareErr: true},
		// Empty components (consecutive/trailing dots) are malformed → incomparable.
		{name: "fortinet: consecutive dots → CompareError (7..0 vs 7.0.0)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7..0", v2: "7.0.0", wantCompareErr: true},
		{name: "fortinet: trailing dot → CompareError (7.2. vs 7.2)", t: ccRangeTypes.RangeTypeFortinetFortios, v1: "7.2.", v2: "7.2", wantCompareErr: true},
		{name: "version (loose): 4-segment v1 < v2", t: ccRangeTypes.RangeTypeVersion, v1: "9.16.19.0", v2: "9.16.20.0", want: -1},
		{name: "version (loose): v1 unparseable → CompareError", t: ccRangeTypes.RangeTypeVersion, v1: "x.y.z.w.q", v2: "1.0", wantCompareErr: true},
		{name: "pan-os: base < hotfix (hashicorp prerelease order would invert this)", t: ccRangeTypes.RangeTypePANOS, v1: "11.2.4", v2: "11.2.4-h1", want: -1},
		{name: "pan-os: hotfix numeric order", t: ccRangeTypes.RangeTypePANOS, v1: "10.2.4-h2", v2: "10.2.4-h10", want: -1},
		{name: "pan-os: equal", t: ccRangeTypes.RangeTypePANOS, v1: "10.2.4-h10", v2: "10.2.4-h10", want: 0},
		{name: "pan-os: 2-segment unparseable → CompareError", t: ccRangeTypes.RangeTypePANOS, v1: "11.2", v2: "11.2.0", wantCompareErr: true},
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
