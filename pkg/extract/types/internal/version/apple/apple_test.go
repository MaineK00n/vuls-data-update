package apple_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/version/apple"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		wantErr bool
	}{
		{name: "three segments", v: "16.5.1"},
		{name: "two segments", v: "26.6"},
		{name: "one segment", v: "26"},
		{name: "rapid security response", v: "16.5.1 (a)"},
		{name: "rapid security response on two segments", v: "26.3 (a)"},
		{name: "rapid security response on one segment", v: "26 (a)"},
		{name: "surrounding space is trimmed", v: " 16.5.1 "},
		{name: "empty", v: "", wantErr: true},
		{name: "letter without space", v: "16.5.1(a)", wantErr: true},
		{name: "multi-char letter", v: "16.5.1 (aa)", wantErr: true},
		{name: "uppercase letter", v: "16.5.1 (A)", wantErr: true},
		{name: "trailing dot", v: "16.5.", wantErr: true},
		{name: "consecutive dots", v: "16..5", wantErr: true},
		{name: "prose", v: "Sierra", wantErr: true},
		{name: "build code", v: "5E133", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := apple.NewVersion(tt.v); (err != nil) != tt.wantErr {
				t.Errorf("NewVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVersion_Compare(t *testing.T) {
	tests := []struct {
		name string
		v    string
		w    string
		want int
	}{
		{
			// The whole reason this package exists: an RSR ships after the
			// base release it patches, and the general-purpose comparators
			// cannot parse the letter form at all.
			name: "a rapid security response comes after its base",
			v:    "16.5.1 (a)", w: "16.5.1", want: 1,
		},
		{name: "rapid security response letters order", v: "16.5.1 (a)", w: "16.5.1 (c)", want: -1},
		{
			// An advisory bounded at 16.5.1 (a) must cover the vulnerable
			// base but not the release carrying the fix.
			name: "the fix release is outside the affected range",
			v:    "16.5.1", w: "16.5.1 (a)", want: -1,
		},
		{name: "a rapid security response sorts before the next patch", v: "16.5.1 (c)", w: "16.5.2", want: -1},
		{name: "minor segments are numeric, not lexical", v: "10.9", w: "10.10", want: -1},
		{name: "major", v: "26.1", w: "15.7.9", want: 1},
		{name: "equal", v: "16.5.1 (a)", w: "16.5.1 (a)", want: 0},
		{name: "missing segments are zero", v: "16.4", w: "16.4.0", want: 0},
		{name: "arity", v: "16.4", w: "16.4.1", want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := apple.NewVersion(tt.v)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			w, err := apple.NewVersion(tt.w)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if got := sign(v.Compare(w)); got != tt.want {
				t.Errorf("Compare() = %d, want %d", got, tt.want)
			}
			// Comparison has to be antisymmetric, or a range bound would
			// answer differently depending on which side it was evaluated
			// from.
			if got := sign(w.Compare(v)); got != -tt.want {
				t.Errorf("Compare() reversed = %d, want %d", got, -tt.want)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
