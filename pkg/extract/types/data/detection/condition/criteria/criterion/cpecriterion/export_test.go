package cpecriterion

// This file re-exports unexported helpers so the external cpecriterion_test
// package can exercise the pattern-set logic. It is compiled only under
// `go test`.

// Relation re-exports relation and its values.
type Relation = relation

const (
	RelationUnknown  = relationUnknown
	RelationDisjoint = relationDisjoint
	RelationEqual    = relationEqual
	RelationSubset   = relationSubset
	RelationSuperset = relationSuperset
	RelationOverlap  = relationOverlap
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
