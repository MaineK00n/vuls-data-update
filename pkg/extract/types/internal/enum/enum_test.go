package enum_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

func TestVocabulary_Compare(t *testing.T) {
	vocabulary := enum.NewVocabulary([]string{"vendor", "cvss_v2", "cvss_v40"})

	tests := []struct {
		name string
		x, y string
		want int
	}{
		{name: "equal known", x: "vendor", y: "vendor", want: 0},
		{name: "declaration order wins over lexicographic", x: "vendor", y: "cvss_v2", want: -1},
		{name: "declaration order, reversed", x: "cvss_v40", y: "cvss_v2", want: +1},
		{name: "known before unknown", x: "cvss_v40", y: "aaa", want: -1},
		{name: "unknown after known", x: "zzz", y: "vendor", want: +1},
		{name: "unknowns order lexicographically", x: "future-a", y: "future-b", want: -1},
		{name: "equal unknown", x: "future-a", y: "future-a", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vocabulary.Compare(tt.x, tt.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVocabulary_Contains(t *testing.T) {
	vocabulary := enum.NewVocabulary([]string{"vendor", "cvss_v2"})
	if !vocabulary.Contains("vendor") {
		t.Errorf("Contains(vendor) = false, want true")
	}
	if vocabulary.Contains("future") {
		t.Errorf("Contains(future) = true, want false")
	}
	if vocabulary.Contains("") {
		t.Errorf(`Contains("") = true, want false`)
	}
}

func TestVocabulary_Values(t *testing.T) {
	vocabulary := enum.NewVocabulary([]string{"a", "b"})
	vs := vocabulary.Values()
	vs[0] = "mutated"
	if got := vocabulary.Values()[0]; got != "a" {
		t.Errorf("Values() must return a copy; vocabulary mutated to %q", got)
	}
}
