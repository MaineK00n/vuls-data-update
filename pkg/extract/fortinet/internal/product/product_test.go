package product_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestBakeVersion(t *testing.T) {
	type args struct {
		cpe     string
		version string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "concrete version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", version: "7.4.3"},
			want: "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
		},
		{
			name: "hyphenated version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*", version: "6.1-2-29"},
			want: "cpe:2.3:o:fortinet:fortiswitch:6.1-2-29:*:*:*:*:*:*:*",
		},
		{
			name:    "invalid cpe",
			args:    args{cpe: "not-a-cpe", version: "1.0.0"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := product.BakeVersion(tt.args.cpe, tt.args.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BakeVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("BakeVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsConcrete(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{v: "7.4.3", want: true},
		{v: "7.4.3.1", want: true},
		{v: "7.4", want: false},
		{v: "7", want: false},
		{v: "24", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.v, func(t *testing.T) {
			if got := product.IsConcrete(tt.v); got != tt.want {
				t.Errorf("IsConcrete(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestTrainRange(t *testing.T) {
	tests := []struct {
		train   string
		want    ccRangeTypes.Range
		wantErr bool
	}{
		{train: "7.0", want: ccRangeTypes.Range{GreaterEqual: "7.0", LessThan: "7.1"}},
		{train: "7", want: ccRangeTypes.Range{GreaterEqual: "7", LessThan: "8"}},
		{train: "6.253", want: ccRangeTypes.Range{GreaterEqual: "6.253", LessThan: "6.254"}},
		{train: "24", want: ccRangeTypes.Range{GreaterEqual: "24", LessThan: "25"}},
		{train: "abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.train, func(t *testing.T) {
			got, err := product.TrainRange(tt.train)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TrainRange(%q) error = %v, wantErr %v", tt.train, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("TrainRange(%q) (-want +got):\n%s", tt.train, diff)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name      string
		wantCPE   string
		wantRange ccRangeTypes.RangeType
		wantOK    bool
	}{
		{name: "FortiOS", wantCPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", wantRange: ccRangeTypes.RangeTypeFortinetFortiOS, wantOK: true},
		{name: "FortiSASE", wantCPE: "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*", wantRange: ccRangeTypes.RangeTypeFortinetFortiSASE, wantOK: true},
		{name: "FortiClientWindows", wantCPE: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", wantRange: ccRangeTypes.RangeTypeFortinetFortiClient, wantOK: true},
		{name: "  FortiProxy  ", wantCPE: "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*", wantRange: ccRangeTypes.RangeTypeFortinetFortiProxy, wantOK: true},
		{name: "Nonexistent Product", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe, rt, ok := product.Resolve(tt.name)
			if ok != tt.wantOK || cpe != tt.wantCPE || rt != tt.wantRange {
				t.Errorf("Resolve(%q) = (%q, %v, %v), want (%q, %v, %v)", tt.name, cpe, rt, ok, tt.wantCPE, tt.wantRange, tt.wantOK)
			}
		})
	}
}

// A product's comparator is per-CPE, so every name sharing a CPE must map it to
// the same range type. A table edit that gives one CPE conflicting range types
// would silently mis-compare at detect time, so guard the invariant here.
func TestNameToProductCPERangeTypeConsistent(t *testing.T) {
	type entry struct {
		rangeType ccRangeTypes.RangeType
		name      string
	}
	byCPE := make(map[string]entry)
	for _, e := range product.ProductEntries() {
		if seen, ok := byCPE[e.CPE]; ok {
			if seen.rangeType != e.RangeType {
				t.Errorf("cpe %q has conflicting range types: %s (product %q) and %s (product %q)", e.CPE, seen.rangeType, seen.name, e.RangeType, e.Name)
			}
			continue
		}
		byCPE[e.CPE] = entry{rangeType: e.RangeType, name: e.Name}
	}
}
