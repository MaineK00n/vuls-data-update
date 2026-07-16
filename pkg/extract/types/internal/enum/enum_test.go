package enum_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

func TestCompare(t *testing.T) {
	vocabulary := []string{"vendor", "cvss_v2", "cvss_v40"}

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
			if got := enum.Compare(vocabulary, tt.x, tt.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
