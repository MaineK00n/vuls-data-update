package cpecriterion

import (
	"testing"
)

// overlapsRef is overlaps by way of the full relation, with no shortcut:
// Table 6-2 for NA, and relateParsed for everything else, ANY being the
// pattern "*".
func overlapsRef(a, b wfnValue) bool {
	switch {
	case a.na:
		return b.na || b.any
	case b.na:
		return a.any
	default:
		return relateParsed(a.p, b.p) != relationDisjoint
	}
}

// diffOverlaps reports how overlaps departs from overlapsRef on the two
// formatted-string values x and y; a value unbindValueFS rejects is skipped.
func diffOverlaps(t *testing.T, x, y string) {
	t.Helper()
	var a, b wfnValue
	if err := unbindValueFS([]byte(x), &a); err != nil {
		return
	}
	if err := unbindValueFS([]byte(y), &b); err != nil {
		return
	}
	if got, want := overlaps(&a, &b), overlapsRef(a, b); got != want {
		t.Errorf("overlaps(%q, %q) = %v, by relation %v", x, y, got, want)
	}
}

var overlapsSeeds = []string{
	"*", "-", "", "?", "??", "?*", "*?",
	"12.0", "12.0.6099.109", "120.0.6099.109", "RC1", "12.0rc1",
	"12.*", "12.0.*", "*.109", "*109", "*2*", "*.0.*", "*",
	"?2.0", "12.?", "??.0", "12.0??", "?2.?",
	`12\.0`, `12\.*`, `8.2\:1`, `1\\`, `\*`, `a\**`,
	"バージョン", "1*2",
}

func TestOverlaps(t *testing.T) {
	for _, x := range overlapsSeeds {
		for _, y := range overlapsSeeds {
			diffOverlaps(t, x, y)
		}
	}
}

func FuzzOverlaps(f *testing.F) {
	for _, x := range overlapsSeeds {
		for _, y := range overlapsSeeds {
			f.Add(x, y)
		}
	}
	f.Fuzz(func(t *testing.T, x, y string) {
		diffOverlaps(t, x, y)
	})
}
