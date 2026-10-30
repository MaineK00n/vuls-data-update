package cpecriterion

import (
	"bytes"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// WFN attributes, in formatted-string order.
const (
	attrPart = iota
	attrVendor
	attrProduct
	attrVersion
	attrUpdate
	attrEdition
	attrLanguage
	attrSwEdition
	attrTargetSw
	attrTargetHw
	attrOther
	attrCount
)

// wfnValue is one WFN attribute value: ANY, NA, or a string. A string keeps
// its unescaped form and its pattern (see parsePattern), computed once so
// that relating values allocates nothing. Both may share memory with the
// formatted string the value was unbound from, so a value lives no longer
// than that (for a packed entry, until the next entry is decoded).
type wfnValue struct {
	any, na bool
	// unescaped is the value with its escaping removed, in its original
	// case: what unescapeWFN gives for the value go-cpe's UnbindFS
	// produces. "ANY" or "NA" for a logical value, as GetString renders it.
	unescaped []byte
	// p is the value as a pattern; ANY is the pattern "*". Unset for NA.
	p pattern
}

// hasWildcards reports whether v is a string carrying unquoted wild cards.
func (v wfnValue) hasWildcards() bool {
	return !v.any && !v.na && (v.p.lead != 0 || v.p.trail != 0)
}

// wfn is a well-formed name as unbindFS produces it.
type wfn [attrCount]wfnValue

var (
	anyValue = wfnValue{any: true, unescaped: []byte("ANY"), p: pattern{lead: unbounded}}
	naValue  = wfnValue{na: true, unescaped: []byte("NA")}
)

// unbindFS unbinds a formatted string to a WFN. It accepts and rejects
// exactly the strings go-cpe's naming.UnbindFS does, and gives each
// attribute the value that function gives, but in the form the matching
// here consumes (see wfnValue) and without go-cpe's per-character string
// building, map and interface boxing, which made unbinding the dominant cost
// of Accept. The one departure: go-cpe panics on a value ending in a lone
// backslash, which is an error here. The rules below follow go-cpe's
// ValidateFS, getCompFS, addQuoting and WellFormedName.Set, quirks
// included; TestUnbindFS checks the two against each other.
func unbindFS(fs string) (wfn, error) {
	if err := validateFS(fs); err != nil {
		return wfn{}, err
	}

	// The values slice this one copy of fs.
	var w wfn
	rest := []byte(fs)
	for a := 0; a < 13; a++ {
		// getCompFS: a field ends at the first colon not preceded by a
		// backslash; a colon at index 0 counts as none.
		i := unescapedColonIndex(rest)
		comp := rest
		if i != 0 {
			comp = rest[:i]
		}
		if i == 0 {
			rest = nil
		} else {
			rest = rest[i+1:]
		}
		if a < 2 {
			continue
		}
		if err := unbindValueFS(comp, &w[a-2]); err != nil {
			return wfn{}, errors.Wrapf(err, "unbind %q", comp)
		}
		// Set checks the part as quoted; "a", "o" and "h" quote to
		// themselves and nothing else quotes to them, so the field itself
		// is compared.
		if a-2 == attrPart && string(comp) != "a" && string(comp) != "o" && string(comp) != "h" {
			return wfn{}, errors.Errorf("unexpected part. expected: %q, actual: %q", []string{"a", "o", "h"}, comp)
		}
	}
	return w, nil
}

// validateFS is go-cpe's ValidateFS: the "cpe:2.3:" prefix in any case, and
// exactly 12 colons not preceded by a backslash, none followed directly by
// another colon.
func validateFS(fs string) error {
	const prefix = "cpe:2.3:"
	if len(fs) < len(prefix) || !strings.EqualFold(fs[:len(prefix)], prefix) {
		return errors.Errorf("unexpected formatted string. expected: %q, actual: %q", "cpe:2.3:...", fs)
	}
	n := 0
	for i := 0; i < len(fs); i++ {
		if fs[i] != ':' || (i > 0 && fs[i-1] == '\\') {
			continue
		}
		n++
		if i < len(fs)-1 && fs[i+1] == ':' {
			return errors.Errorf("unexpected formatted string. found an empty component: %q", fs)
		}
	}
	if n != 12 {
		return errors.Errorf("unexpected number of components. expected: %d, actual: %d, formatted string: %q", 12, n, fs)
	}
	return nil
}

// unescapedColonIndex is go-cpe's GetUnescapedColonIndex: the index of the
// first colon not directly preceded by a backslash, or 0 if there is none.
func unescapedColonIndex(s []byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i == 0 || s[i-1] != '\\') {
			return i
		}
	}
	return 0
}

// unbindValueFS is go-cpe's unbindValueFS followed by the checks
// WellFormedName.Set applies to a string. The value is written to v in
// place rather than returned: copying a wfnValue out and in again was a
// third of the cost of unbinding a packed entry.
func unbindValueFS(s []byte, v *wfnValue) error {
	switch string(s) {
	case "*":
		*v = anyValue
		return nil
	case "-":
		*v = naValue
		return nil
	}

	simple, upper := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !simpleByte(c) {
			simple = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			upper = true
		}
	}
	if simple {
		setSimpleValue(v, s, upper)
		return nil
	}

	// Anything else is quoted as go-cpe quotes it and checked on that.
	q, err := addQuoting(string(s))
	if err != nil {
		return err
	}
	if err := validateStringValue(q); err != nil {
		return err
	}
	// The pattern and the unescaped form are read off the formatted string
	// directly: quoting only adds a backslash before a character that is
	// not a wild card, so the wild cards sit at the same ends and unescaping
	// either form gives the same string.
	*v = wfnValue{unescaped: unescapeWFN(s), p: parsePattern(s)}
	return nil
}

// simpleByte reports whether c can be part of a simple value: printable
// ASCII that is not a wild card or a backslash. Nearly every value NVD
// publishes is simple. go-cpe quotes each character of such a value that is
// not a letter, digit or "_" and accepts the result (every punctuation mark
// is then quoted, and nothing is blank or unprintable); the value unescapes
// to itself and its pattern is the value lower-cased with no wild cards.
func simpleByte(c byte) bool {
	return '!' <= c && c <= '~' && c != '\\' && c != '*' && c != '?'
}

// setSimpleValue sets v to the value of s, a simple value (see simpleByte)
// other than "-", with upper reporting whether s has an upper-case letter.
// Nothing is allocated unless it has.
func setSimpleValue(v *wfnValue, s []byte, upper bool) {
	core := s
	if upper {
		core = bytes.ToLower(s)
	}
	*v = wfnValue{unescaped: s, p: pattern{core: core}}
}

// packedWFN returns the WFN unbindReduced fills for the entries packed for
// the criterion c: its part, vendor and product, which every entry shares,
// and ANY elsewhere.
func packedWFN(c *wfn) wfn {
	var m wfn
	m[attrPart], m[attrVendor], m[attrProduct] = c[attrPart], c[attrVendor], c[attrProduct]
	for a := attrVersion; a < attrCount; a++ {
		m[a] = anyValue
	}
	return m
}

// unbindReduced unbinds a packed entry from its reduced form (see
// PackCPEMatches) into m, without restoring its formatted string: m comes
// from packedWFN, or from a previous call, and only the attributes after
// the product are written, those read from e and the ones e omits reset to
// ANY. It accepts exactly the entries Unpack followed by unbindFS accepts,
// with the same values. The full name is prefix (the criterion's
// "cpe:2.3:part:vendor:product:") and e's attributes joined with ":" and
// padded to 8, so e must hold at most 8, each a valid value, and none empty
// but the eighth when it is e's last: go-cpe rejects an empty component by
// the "::" it makes, which a trailing one does not, and reads it as the
// empty string.
// go-cpe reads a colon right after a backslash as escaped whichever way the
// backslash itself is quoted, while PackCPEMatches splits on a backslash
// escaping the character after it; the two agree unless an attribute ends
// in a backslash, and such an entry is unbound from its full name, as
// Unpack would restore it (its part, vendor and product unbind to the
// criterion's, so m keeps them).
func unbindReduced(prefix string, e []byte, m *wfn) error {
	// The attributes are split as splitFS splits them, a backslash escaping
	// the character after it. (Classifying each attribute in this same scan
	// rather than in unbindValueFS's was measured slower: the extra
	// branches per byte cost more than the second pass.)
	a, start := attrVersion, 0
	for i := 0; ; i++ {
		end := len(e)
		if i < len(e) {
			switch e[i] {
			case '\\':
				i++
				continue
			case ':':
				end = i
			default:
				continue
			}
		}
		attr := e[start:end]
		if len(attr) > 0 && attr[len(attr)-1] == '\\' {
			full, err := unbindFS(string(fullName(prefix, e)))
			if err != nil {
				return err
			}
			*m = full
			return nil
		}
		if a == attrCount {
			return errors.Errorf("unexpected number of attributes after the product. expected: at most 8, actual: more, entry: %q", e)
		}
		if len(attr) == 0 && (a != attrOther || end != len(e)) {
			return errors.Errorf("unexpected formatted string. found an empty component: %q", e)
		}
		if err := unbindValueFS(attr, &m[a]); err != nil {
			return errors.Wrapf(err, "unbind %q", attr)
		}
		a++
		if end == len(e) {
			break
		}
		start = i + 1
	}
	for ; a < attrCount; a++ {
		if !m[a].any {
			m[a] = anyValue
		}
	}
	return nil
}

// allANY reports whether q has ANY on each of attrs, and so overlaps every
// WFN there.
func allANY(q *wfn, attrs []int) bool {
	for _, attr := range attrs {
		if !q[attr].any {
			return false
		}
	}
	return true
}

// addQuoting is go-cpe's addQuoting: copy quoted characters with their
// escaping, keep "*" only at either end and "?" only in a run at either end,
// and quote every other character that is not a letter, digit or "_", byte
// by byte.
func addQuoting(s string) (string, error) {
	var b strings.Builder
	b.Grow(2 * len(s))
	embedded := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_':
			b.WriteByte(c)
			i++
			embedded = true
		case c == '\\':
			if i+1 >= len(s) {
				return "", errors.Errorf("unexpected trailing backslash in %q", s)
			}
			b.WriteString(s[i : i+2])
			i += 2
			embedded = true
		case c == '*':
			if i != 0 && i != len(s)-1 {
				return "", errors.Errorf("unexpected embedded unquoted * in %q", s)
			}
			b.WriteByte(c)
			i++
			embedded = true
		case c == '?':
			valid := i == 0 || i == len(s)-1 ||
				!embedded && i > 0 && s[i-1] == '?' ||
				embedded && i+1 < len(s) && s[i+1] == '?'
			if !valid {
				return "", errors.Errorf("unexpected embedded unquoted ? in %q", s)
			}
			b.WriteByte(c)
			i++
			embedded = false
		default:
			b.WriteByte('\\')
			b.WriteByte(c)
			i++
			embedded = true
		}
	}
	return b.String(), nil
}

// validateStringValue is go-cpe's ValidateStringValue, run on the quoted
// value.
func validateStringValue(s string) error {
	if strings.HasPrefix(s, "**") || strings.HasSuffix(s, "**") {
		return errors.Errorf("unexpected * in sequence in %q", s)
	}
	prev := ' '
	for i, r := range s {
		if !unicode.IsPrint(r) {
			return errors.Errorf("unexpected non printable character in %q", s)
		}
		if unicode.IsSpace(r) {
			return errors.Errorf("unexpected whitespace in %q", s)
		}
		if unicode.IsPunct(r) && prev != '\\' && r != '\\' {
			if r == '*' && i != 0 && i != len(s)-1 {
				return errors.Errorf("unexpected embedded * in %q", s)
			}
			if r != '*' && r != '?' && r != '_' {
				return errors.Errorf("unexpected unquoted punctuation in %q", s)
			}
		}
		prev = r
	}
	if strings.Contains(s, "?") && s != "?" && containsQuestions(strings.Trim(s, "?")) {
		return errors.Errorf("unexpected embedded ? in %q", s)
	}
	switch s {
	case "*":
		return errors.Errorf("unexpected single * as a string value")
	case `\-`:
		return errors.Errorf("unexpected quoted hyphen as a string value")
	}
	return nil
}

// containsQuestions is go-cpe's ContainsQuestions: a "?" whose preceding
// character is not a backslash.
func containsQuestions(s string) bool {
	prev := ' '
	for _, r := range s {
		if r == '?' && prev != '\\' {
			return true
		}
		prev = r
	}
	return false
}
