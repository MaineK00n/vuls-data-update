package cpecriterion

// This file re-exports unexported helpers so the external cpecriterion_test
// package can exercise the pattern-set logic. It is compiled only under
// `go test`.

// PatternRelation re-exports patternRelation and its values.
type PatternRelation = patternRelation

const (
	PatternUnknown  = patternUnknown
	PatternDisjoint = patternDisjoint
	PatternEqual    = patternEqual
	PatternSubset   = patternSubset
	PatternSuperset = patternSuperset
	PatternOverlap  = patternOverlap
)

// Unbounded re-exports unbounded.
const Unbounded = unbounded

// Pattern mirrors the unexported pattern with exported fields, letting the
// external test inspect the parsed form.
type Pattern struct {
	Lead, Trail int
	Core        string
}

// ParsePattern wraps parsePattern, returning the parsed form as an exported
// Pattern.
func ParsePattern(s string) Pattern {
	p := parsePattern(s)
	return Pattern{Lead: p.lead, Trail: p.trail, Core: p.core}
}

// RelatePatterns re-exports relatePatterns.
var RelatePatterns = relatePatterns
