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
	// pattern is the value as a pattern; ANY is the pattern "*". Unset for
	// NA. Embedded for its name; its fields are set and read as promoted
	// ones (v.lead), and v.pattern names the pattern as a whole.
	pattern
}

// hasWildcards reports whether v is a string carrying unquoted wild cards.
func (v wfnValue) hasWildcards() bool {
	return !v.any && !v.na && (v.lead != 0 || v.trail != 0)
}

// wfn is a well-formed name as unbindFS produces it.
type wfn [attrCount]wfnValue

var (
	anyValue = wfnValue{any: true, unescaped: []byte("ANY"), lead: unbounded}
	naValue  = wfnValue{na: true, unescaped: []byte("NA")}
)

// unbindFS unbinds a formatted string to a WFN. It accepts the strings
// go-cpe's naming.UnbindFS accepts and gives each attribute the value that
// function gives, but in the form the matching here consumes (see wfnValue)
// and without go-cpe's per-character string building, map and interface
// boxing, which made unbinding the dominant cost of Accept. The rules below
// follow go-cpe's ValidateFS, getCompFS, addQuoting and WellFormedName.Set,
// quirks included, and depart from them where go-cpe falls short of the
// grammar (NISTIR 7695 §5.3.2 and §6.2.3), in which a backslash always
// quotes the character after it:
//   - a colon after a quoted backslash ("\\:") is a component separator;
//     go-cpe looks only at the byte before a colon, reads it as quoted, and
//     rejects the name on its colon count.
//   - a value ending in a lone backslash is an error; go-cpe panics.
//
// FuzzUnbindFS checks the two against each other outside those cases.
func unbindFS(fs string) (wfn, error) {
	attrs, err := attributesFS(fs)
	if err != nil {
		return wfn{}, errors.Wrap(err, "validate formatted string")
	}

	// The values slice this one copy of the attributes.
	var w wfn
	rest := []byte(attrs)
	for a := range attrCount {
		i := unescapedColonIndex(rest)
		comp := rest
		if i < 0 {
			rest = nil
		} else {
			comp, rest = rest[:i], rest[i+1:]
		}
		if err := unbindValueFS(comp, &w[a]); err != nil {
			return wfn{}, errors.Wrapf(err, "unbind %q", comp)
		}
		// Set checks the part as quoted; "a", "o" and "h" quote to
		// themselves and nothing else quotes to them, so the field itself
		// is compared.
		if a == attrPart && string(comp) != "a" && string(comp) != "o" && string(comp) != "h" {
			return wfn{}, errors.Errorf("unexpected part. expected: %q, actual: %q", []string{"a", "o", "h"}, comp)
		}
	}
	return w, nil
}

// fsPrefix opens every formatted string, in any case.
const fsPrefix = "cpe:2.3:"

// attributesFS checks fs as go-cpe's ValidateFS does, with the grammar's
// colon rule, and returns the part after the "cpe:2.3:" prefix, which holds
// the attributes: the prefix in any case, then exactly attrCount components
// separated by unquoted colons, none of them empty but the last.
func attributesFS(fs string) (string, error) {
	if len(fs) < len(fsPrefix) || !strings.EqualFold(fs[:len(fsPrefix)], fsPrefix) {
		return "", errors.Errorf("unexpected formatted string. expected: %q, actual: %q", "cpe:2.3:...", fs)
	}
	attrs := fs[len(fsPrefix):]
	if strings.HasPrefix(attrs, ":") {
		return "", errors.Errorf("unexpected formatted string. found an empty component: %q", fs)
	}
	n := 1
	for i := 0; i < len(attrs); i++ {
		switch attrs[i] {
		case '\\':
			i++
		case ':':
			n++
			// A trailing colon leaves the last attribute empty; go-cpe
			// accepts that and reads it as the empty string, so does this.
			if i < len(attrs)-1 && attrs[i+1] == ':' {
				return "", errors.Errorf("unexpected formatted string. found an empty component: %q", fs)
			}
		}
	}
	if n != attrCount {
		return "", errors.Errorf("unexpected number of attributes. expected: %d, actual: %d, formatted string: %q", attrCount, n, fs)
	}
	return attrs, nil
}

// unescapedColonIndex is go-cpe's GetUnescapedColonIndex with the grammar's
// colon rule: the index of the first unquoted colon in s, or -1 if there is
// none.
func unescapedColonIndex(s []byte) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ':':
			return i
		}
	}
	return -1
}

// unbindValueFS is go-cpe's unbindValueFS followed by the checks
// WellFormedName.Set applies to a string. The value is written to v in
// place rather than returned: copying a wfnValue out and in again was a
// third of the cost of unbinding a packed entry. Hot path: see the package documentation before changing it.
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
	for i := range s {
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
		return errors.Wrap(err, "quote value")
	}
	if err := validateStringValue(q); err != nil {
		return errors.Wrap(err, "validate quoted value")
	}
	// The pattern and the unescaped form are read off the formatted string
	// directly: quoting only adds a backslash before a character that is
	// not a wild card, so the wild cards sit at the same ends and unescaping
	// either form gives the same string.
	*v = wfnValue{unescaped: unescapeWFN(s), pattern: parsePattern(s)}
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
	*v = wfnValue{unescaped: s, core: core}
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
// with the same values. The full name is the criterion's
// "cpe:2.3:part:vendor:product:" prefix and e's attributes joined with ":"
// and padded to 8, so e must hold at most 8, each a valid value, and none
// empty but the eighth when it is e's last: go-cpe rejects an empty component
// by the "::" it makes, which a trailing one does not, and reads it as the
// empty string. Hot path: see the package documentation before changing it.
func unbindReduced(e []byte, m *wfn) error {
	// The attributes are split on the same rule as splitFS and unbindFS: a
	// backslash quotes the byte after it.
	//
	// Each attribute's bytes are then read a second time by unbindValueFS,
	// which classifies it; folding that classification into this scan was
	// measured slower, as the extra branches per byte cost more than the
	// second, simpler pass.
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
		if a == attrCount {
			return errors.Errorf("unexpected number of attributes after the product. expected: at most 8, actual: more, entry: %q", e)
		}
		// An empty attribute makes "::" in the full name, which go-cpe
		// rejects, unless it is the eighth and e's last: that is the full
		// name's trailing colon, which go-cpe accepts as an empty value.
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
	// embedded is go-cpe's flag: the previous unquoted character was not
	// a "?" (a quoted "\?" counts as not one). It lets a "?" continue a
	// run or start one after other characters; that still passes a run in
	// the middle ("a??b"), which validateStringValue rejects afterwards.
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
