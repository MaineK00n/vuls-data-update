package openssh_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/version/openssh"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		wantErr bool
	}{
		{name: "two segments", v: "9.9"},
		{name: "three segments", v: "3.7.1"},
		{name: "portable", v: "9.9p1"},
		{name: "portable of three segments", v: "3.7.1p2"},
		{name: "one segment", v: "9"},
		{name: "uppercase suffix", v: "9.9P1"},
		{name: "empty", v: "", wantErr: true},
		{name: "prose", v: "prior to 7.6", wantErr: true},
		{name: "suffix without a number", v: "9.9p", wantErr: true},
		{name: "unknown suffix", v: "9.9rc1", wantErr: true},
		{name: "trailing dot", v: "9.9.", wantErr: true},
		{name: "date", v: "2025-02-18", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := openssh.NewVersion(tt.v); (err != nil) != tt.wantErr {
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
			// The whole reason this package exists: hashicorp's comparator
			// reads p1 as a pre-release and answers the other way round.
			name: "a portable release comes after its base",
			v:    "9.9p1", w: "9.9", want: 1,
		},
		{name: "portable levels order", v: "9.9p1", w: "9.9p2", want: -1},
		{
			// An advisory affecting up to 9.9p1 must not cover the 9.9p2 that
			// fixes it.
			name: "the fix release is outside the affected range",
			v:    "9.9p2", w: "9.9p1", want: 1,
		},
		{name: "minor segments are numeric, not lexical", v: "9.9", w: "9.10", want: -1},
		{name: "major", v: "10.0", w: "9.9p1", want: 1},
		{name: "equal", v: "9.9p1", w: "9.9p1", want: 0},
		{name: "missing segments are zero", v: "3.7", w: "3.7.0", want: 0},
		{name: "arity", v: "3.7", w: "3.7.1", want: -1},
		{name: "portable against a later base", v: "9.7p1", w: "9.8", want: -1},
		{name: "case of the suffix does not matter", v: "9.9P1", w: "9.9p1", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := openssh.NewVersion(tt.v)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			w, err := openssh.NewVersion(tt.w)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if got := sign(v.Compare(w)); got != tt.want {
				t.Errorf("Compare() = %d, want %d", got, tt.want)
			}
			// Comparison has to be antisymmetric, or a range bound would answer
			// differently depending on which side it was evaluated from.
			if got := sign(w.Compare(v)); got != -tt.want {
				t.Errorf("reversed Compare() = %d, want %d", got, -tt.want)
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
