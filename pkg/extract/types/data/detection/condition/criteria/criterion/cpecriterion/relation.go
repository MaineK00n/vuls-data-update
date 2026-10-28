package cpecriterion

import (
	"strings"

	"github.com/knqyf263/go-cpe/common"
)

// relation is the set relation between two WFN attribute values: the
// relations of NISTIR 7696 Table 6-2 (=, ⊂, ⊃, ≠) plus a partial overlap for
// the cells the table leaves undefined, two values that both carry unquoted
// wild cards. Those are decidable because NISTIR 7695 §5.3.2 restricts where
// wild cards may appear: an unquoted "*" only at the beginning and/or end of
// a value, an unquoted "?" only in a run at the beginning and/or end. Every
// legal pattern therefore reads
//
//	L core R    L, R ∈ { "*", "?"×n (n ≥ 0) }    core: literal, no wild cards
//
// and, as "?" matches zero or one character (7696 §6.3), denotes the set of
// strings l+core+r with 0 ≤ |l| ≤ a and 0 ≤ |r| ≤ b, where a and b are n for
// a "?" run and unbounded for "*". A concrete value is the pattern with a = b
// = 0 and ANY is "*", so one comparison of (a, core, b) triples covers the
// whole table; see pattern.subsetOf and pattern.intersects.
type relation int

const (
	// relationUnknown is the zero value: a relation that was never computed.
	// relatePatterns never returns it.
	relationUnknown relation = iota
	relationDisjoint
	relationEqual
	// relationSubset: every string of the first pattern is in the second.
	relationSubset
	// relationSuperset: every string of the second pattern is in the first.
	relationSuperset
	// relationOverlap: the patterns intersect but neither contains the other.
	relationOverlap
)

// relateValues returns the relation of a to b, two WFN attribute values as
// WellFormedName.Get returns them: a string (concrete or pattern) or a
// LogicalValue. NA is the only value that is not a set of strings: it equals
// NA, is within ANY, and is disjoint from everything else (Table 6-2).
func relateValues(a, b any) relation {
	la, aLogical := a.(common.LogicalValue)
	lb, bLogical := b.(common.LogicalValue)
	switch {
	case aLogical && la.IsNA():
		switch {
		case bLogical && lb.IsNA():
			return relationEqual
		case bLogical && lb.IsANY():
			return relationSubset
		default:
			return relationDisjoint
		}
	case bLogical && lb.IsNA():
		if aLogical && la.IsANY() {
			return relationSuperset
		}
		return relationDisjoint
	default:
		return relatePatterns(patternString(a), patternString(b))
	}
}

// patternString renders a non-NA attribute value as a pattern: ANY is "*",
// a string is itself.
func patternString(v any) string {
	if lv, ok := v.(common.LogicalValue); ok && lv.IsANY() {
		return "*"
	}
	return v.(string)
}

// hasWildcards reports whether a string attribute value carries unquoted wild
// cards, by the same quoting rule parsePattern applies: a wild card is quoted
// by an odd number of preceding backslashes, so "a\\*" (an escaped
// backslash, then "*") is a pattern. go-cpe's common.ContainsWildcards looks
// only at the character before the wild card and would call it concrete.
func hasWildcards(s string) bool {
	p := parsePattern(s)
	return p.lead != 0 || p.trail != 0
}

// relatePatterns returns the relation of x to y, two WFN attribute values in
// escaped string form, either of which may carry unquoted wild cards.
// Comparison is case-insensitive (7696 §6.2).
func relatePatterns(x, y string) relation {
	a, b := parsePattern(x), parsePattern(y)
	ab, ba := a.subsetOf(b), b.subsetOf(a)
	switch {
	case ab && ba:
		return relationEqual
	case ab:
		return relationSubset
	case ba:
		return relationSuperset
	case a.intersects(b):
		return relationOverlap
	default:
		return relationDisjoint
	}
}

// unbounded is the lead / trail of a "*" wild card: any number of characters.
const unbounded = -1

// pattern is the (a, core, b) form of a wild-card attribute value: at most
// lead characters, then core, then at most trail characters.
type pattern struct {
	lead, trail int
	core        string // unescaped, lower-cased
}

// parsePattern splits a WFN attribute value into its leading wild cards, its
// literal core and its trailing wild cards. A quoted "\*" or "\?" is literal
// and belongs to the core.
func parsePattern(s string) pattern {
	var p pattern
	start, end := 0, len(s)
	if start < end && s[start] == '*' {
		p.lead = unbounded
		start++
	} else {
		for start < end && s[start] == '?' {
			p.lead++
			start++
		}
	}
	if start < end && s[end-1] == '*' && unquotedAt(s, end-1) {
		p.trail = unbounded
		end--
	} else {
		for start < end && s[end-1] == '?' && unquotedAt(s, end-1) {
			p.trail++
			end--
		}
	}
	p.core = strings.ToLower(unescapeWFN(s[start:end]))
	return p
}

// unquotedAt reports whether the character at s[i] is unquoted: preceded by
// an even number of backslashes.
func unquotedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 0
}

// within reports whether every length in [0, n] is within [0, limit]; n or
// limit may be unbounded.
func within(n, limit int) bool {
	if limit == unbounded {
		return true
	}
	return n != unbounded && n <= limit
}

// plus adds k to a bound, keeping unbounded.
func plus(n, k int) int {
	if n == unbounded {
		return unbounded
	}
	return n + k
}

// subsetOf reports whether every string of a is a string of b.
//
// The strings of a are l+a.core+r for arbitrary l and r, so consider one whose
// l and r are as long as a allows and made of a character absent from b.core:
// b can only match it with b.core found inside a.core, at a position i whose
// surroundings (i plus the longest l, the rest of a.core plus the longest r)
// still fit under b's bounds. Conversely such an i matches every string of a.
// When b.core is empty, b is every string of length at most b.lead+b.trail.
func (a pattern) subsetOf(b pattern) bool {
	if b.core == "" {
		if b.lead == unbounded || b.trail == unbounded {
			return true
		}
		if a.lead == unbounded || a.trail == unbounded {
			return false
		}
		return a.lead+len(a.core)+a.trail <= b.lead+b.trail
	}
	for i := 0; i+len(b.core) <= len(a.core); i++ {
		if a.core[i:i+len(b.core)] != b.core {
			continue
		}
		if within(plus(a.lead, i), b.lead) && within(plus(a.trail, len(a.core)-i-len(b.core)), b.trail) {
			return true
		}
	}
	return false
}

// intersects reports whether some string is in both a and b.
//
// Place b.core at offset d from a.core; the two cores must agree where they
// overlap, and the shortest string realising that placement (cores as far
// left as possible, nothing after the later core) must fit under both
// patterns' bounds. Placements with a gap between the cores need longer
// surroundings than the adjacent placement, so offsets beyond the cores'
// lengths add nothing.
func (a pattern) intersects(b pattern) bool {
	for d := -len(b.core); d <= len(a.core); d++ {
		lo, hi := max(0, d), min(len(a.core), d+len(b.core))
		if lo < hi && a.core[lo:hi] != b.core[lo-d:hi-d] {
			continue
		}
		pa := max(0, -d)
		pb := pa + d
		n := max(pa+len(a.core), pb+len(b.core))
		if within(pa, a.lead) && within(pb, b.lead) && within(n-pa-len(a.core), a.trail) && within(n-pb-len(b.core), b.trail) {
			return true
		}
	}
	return false
}
