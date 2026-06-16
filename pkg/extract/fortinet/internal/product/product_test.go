package product_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestToCPE(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{name: "FortiOS", want: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "FortiClientWindows", want: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "  FortiProxy  ", want: "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "Nonexistent Product", want: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := product.ToCPE(tt.name)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("ToCPE(%q) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestBakeVersion(t *testing.T) {
	got, err := product.BakeVersion("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.4.3")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if want := "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*"; got != want {
		t.Errorf("BakeVersion() = %q, want %q", got, want)
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
		{train: "7.0", want: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet, GreaterEqual: "7.0", LessThan: "7.1"}},
		{train: "7", want: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet, GreaterEqual: "7", LessThan: "8"}},
		{train: "6.253", want: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet, GreaterEqual: "6.253", LessThan: "6.254"}},
		{train: "24", want: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinet, GreaterEqual: "24", LessThan: "25"}},
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
