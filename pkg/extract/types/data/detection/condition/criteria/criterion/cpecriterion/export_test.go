package cpecriterion

// This file re-exports unexported helpers so the external cpecriterion_test
// package can exercise the pattern-set logic and the unbinding of formatted
// strings. It is compiled only under `go test`.

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

func exportPattern(p pattern) Pattern {
	return Pattern{Lead: p.lead, Trail: p.trail, Core: string(p.core)}
}

func importPattern(p Pattern) pattern {
	return pattern{lead: p.Lead, trail: p.Trail, core: []byte(p.Core)}
}

// ParsePattern wraps parsePattern, returning the parsed form as an exported
// Pattern.
func ParsePattern(s string) Pattern {
	return exportPattern(parsePattern([]byte(s)))
}

// RelatePatterns re-exports relatePatterns.
var RelatePatterns = relatePatterns

// RelateParsed wraps relateParsed.
func RelateParsed(a, b Pattern) Relation {
	return relateParsed(importPattern(a), importPattern(b))
}

// The WFN attribute indices, re-exported.
const (
	AttrPart      = attrPart
	AttrVendor    = attrVendor
	AttrProduct   = attrProduct
	AttrVersion   = attrVersion
	AttrUpdate    = attrUpdate
	AttrEdition   = attrEdition
	AttrLanguage  = attrLanguage
	AttrSwEdition = attrSwEdition
	AttrTargetSw  = attrTargetSw
	AttrTargetHw  = attrTargetHw
	AttrOther     = attrOther
	AttrCount     = attrCount
)

// Value mirrors the unexported wfnValue with exported, comparable fields.
type Value struct {
	Any, NA   bool
	Unescaped string
	Pattern   Pattern
}

func exportValue(v wfnValue) Value {
	return Value{Any: v.any, NA: v.na, Unescaped: string(v.unescaped), Pattern: exportPattern(v.p)}
}

func importValue(v Value) wfnValue {
	return wfnValue{any: v.Any, na: v.NA, unescaped: []byte(v.Unescaped), p: importPattern(v.Pattern)}
}

// AnyValue and NAValue are the Values of the two logical values.
var AnyValue, NAValue = exportValue(anyValue), exportValue(naValue)

// StringValue is the Value of a WFN string value in the quoted form go-cpe
// produces: its unescaped form and its pattern.
func StringValue(v string) Value {
	return exportValue(wfnValue{unescaped: unescapeWFN([]byte(v)), p: parsePattern([]byte(v))})
}

// WFN mirrors the unexported wfn.
type WFN [AttrCount]Value

func exportWFN(w wfn) WFN {
	var e WFN
	for i, v := range w {
		e[i] = exportValue(v)
	}
	return e
}

func importWFN(w WFN) wfn {
	var m wfn
	for i, v := range w {
		m[i] = importValue(v)
	}
	return m
}

// UnbindFS wraps unbindFS.
func UnbindFS(fs string) (WFN, error) {
	w, err := unbindFS(fs)
	if err != nil {
		return WFN{}, err
	}
	return exportWFN(w), nil
}

// UnbindValueFS wraps unbindValueFS.
func UnbindValueFS(s string) (Value, error) {
	var v wfnValue
	if err := unbindValueFS([]byte(s), &v); err != nil {
		return Value{}, err
	}
	return exportValue(v), nil
}

// PackedWFN wraps packedWFN.
func PackedWFN(c WFN) WFN {
	m := importWFN(c)
	return exportWFN(packedWFN(&m))
}

// UnbindReduced wraps unbindReduced: m is converted in, written to by
// unbindReduced, and converted back out, whether or not it errs.
func UnbindReduced(e string, m *WFN) error {
	w := importWFN(*m)
	err := unbindReduced([]byte(e), &w)
	*m = exportWFN(w)
	return err
}

// FullName wraps fullName.
func FullName(prefix, e string) string {
	return string(fullName(prefix, []byte(e)))
}

// Overlaps wraps overlaps.
func Overlaps(a, b Value) bool {
	x, y := importValue(a), importValue(b)
	return overlaps(&x, &y)
}
