package cpecriterion

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"

	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// PackedEncoding names the text encoding of CPEMatchesPacked.Data. It is a
// string so that unmarshaling never validates against the known set: data
// produced by a newer vuls-data-update (carrying an encoding this build does
// not know) still round-trips losslessly, and Unpack reports it as an
// *UnsupportedPackedEncodingError instead of guessing.
type PackedEncoding string

const (
	// PackedEncodingFC: front coding. The reduced entries (see
	// PackCPEMatches) are sorted and each is written as one character
	// holding the length of the prefix it shares with the previous entry,
	// followed by the remainder; entries are joined with "|". The length
	// character is the length plus '0', so "0".."9" read as themselves and
	// ":".."[" continue to 43, the cap; a longer shared prefix is cut at 43
	// and the rest is written out. The prefix never ends between a backslash
	// and the character it escapes, so the remainder always starts a new
	// character of the formatted string. '"' and '\' never occur as length
	// characters, so the text needs no escaping in JSON, and a formatted
	// string never contains an unquoted "|" or any whitespace, so "|" is an
	// unambiguous separator.
	//
	//	entries 10.0.0, 10.0.1, 10.0.2  →  "010.0.0|51|52"
	PackedEncodingFC PackedEncoding = "fc"
)

// PackedEncodings returns every PackedEncoding this build knows, in
// declaration order. Consumers (vuls2, vuls0) diff this list against a newer
// vuls-data-update in CI to detect enum additions that require a dependency
// bump. Values are never removed or renamed: either would leave already
// extracted data undecodable by builds that follow. Where a new value is
// declared does not matter to consumers. The declaration order only fixes the
// output order of the build that writes the data (Compare); nothing ranks
// values across builds, so a value's rank need not agree between a build that
// knows it and one that does not.
func PackedEncodings() []PackedEncoding {
	return []PackedEncoding{PackedEncodingFC}
}

// Compare orders e against f by vocabulary rank — the declaration order of
// PackedEncodings(). Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (e PackedEncoding) Compare(f PackedEncoding) int {
	return packedEncodingVocabulary.Compare(e, f)
}

var packedEncodingVocabulary = enum.NewVocabulary(PackedEncodings())

const (
	fcLengthBase = '0'
	fcLengthMax  = '[' - fcLengthBase // 43; the next character is '\'
	fcSeparator  = '|'
)

// CPEMatchesPacked holds concrete CPE names the criterion also covers, in a
// compact text form. It complements CPEMatches rather than replacing it:
// CPEMatches keeps the entries a Range cannot evaluate (out-of-range
// exceptions, non-semver versions, the whole enumeration of an unevaluable
// range), while the packed set carries the entries the Range already covers
// — every concrete name the source enumerated inside the range — so that a
// query whose version is a name-matching pattern ("12.*"), which no Range
// can evaluate, still finds them by name. A concrete query never needs the
// packed set: the Range answers for it.
//
// Readers that predate this field ignore it and keep evaluating CPEMatches
// exactly as before, which is why CPEMatches is not trimmed in its favour.
//
// Data is produced by PackCPEMatches and read back by Unpack; both are
// scoped to the criterion's own CPE, since every packed entry shares its
// part, vendor and product and only the trailing attributes are stored.
type CPEMatchesPacked struct {
	Encoding PackedEncoding `json:"encoding,omitempty"`
	Data     string         `json:"data,omitempty"`
}

func comparePacked(x, y *CPEMatchesPacked) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return +1
	default:
		return cmp.Or(
			x.Encoding.Compare(y.Encoding),
			cmp.Compare(x.Data, y.Data),
		)
	}
}

// Packable reports whether m can be packed against criterion: whether it
// shares the criterion's part, vendor and product byte for byte. A criterion
// whose product is a wildcard, for example, enumerates concrete products that
// do not; such an entry belongs in CPEMatches, where the whole name is kept.
func Packable(criterion, m CPE) bool {
	prefix, err := pvpPrefix(string(criterion))
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(m), prefix)
}

// PackCPEMatches encodes matches, which must all share criterion's part,
// vendor and product (see Packable), as PackedEncodingFC. Each entry is
// reduced to its attributes after the product with the trailing "*"
// attributes dropped ("cpe:2.3:a:v:p:12.0:beta1:*:*:*:*:*:*" becomes
// "12.0:beta1"; escaping is left as is), then the reduced strings are sorted,
// deduplicated and front-coded. An entry that does not share the criterion's
// part, vendor and product is an error: it belongs in CPEMatches, where the
// whole name is kept.
func PackCPEMatches(criterion CPE, matches []CPE) (*CPEMatchesPacked, error) {
	prefix, err := pvpPrefix(string(criterion))
	if err != nil {
		return nil, errors.Wrapf(err, "pvp prefix of %q", string(criterion))
	}

	entries := make([]string, 0, len(matches))
	for _, m := range matches {
		rest, ok := strings.CutPrefix(string(m), prefix)
		if !ok {
			return nil, errors.Errorf("cpe match does not share the criterion part, vendor and product. criterion: %q, match: %q", string(criterion), string(m))
		}
		attrs := splitFS(rest, ':')
		if len(attrs) != 8 {
			return nil, errors.Errorf("unexpected number of attributes after the product. expected: 8, actual: %d, match: %q", len(attrs), string(m))
		}
		for len(attrs) > 0 && attrs[len(attrs)-1] == "*" {
			attrs = attrs[:len(attrs)-1]
		}
		entries = append(entries, strings.Join(attrs, ":"))
	}
	slices.Sort(entries)
	entries = slices.Compact(entries)

	var b strings.Builder
	prev := ""
	for i, e := range entries {
		n := 0
		for n < len(e) && n < len(prev) && n < fcLengthMax && e[n] == prev[n] {
			n++
		}
		// Never cut between a backslash and the character it escapes
		// (whether the entries diverge there or the cap falls there): the
		// remainder would then start with a bare escaped character, and if
		// that character is the separator the packed text is ambiguous.
		if splitsEscape(e, n) {
			n--
		}
		if i > 0 {
			b.WriteByte(fcSeparator)
		}
		b.WriteByte(byte(fcLengthBase + n))
		b.WriteString(e[n:])
		prev = e
	}
	return &CPEMatchesPacked{Encoding: PackedEncodingFC, Data: b.String()}, nil
}

// Unpack restores the CPE names packed for criterion by PackCPEMatches. The
// names come back sorted by their reduced form.
func (p *CPEMatchesPacked) Unpack(criterion CPE) ([]CPE, error) {
	if p == nil {
		return nil, nil
	}
	if p.Encoding != PackedEncodingFC {
		return nil, &UnsupportedPackedEncodingError{Encoding: p.Encoding}
	}
	prefix, err := pvpPrefix(string(criterion))
	if err != nil {
		return nil, errors.Wrapf(err, "pvp prefix of %q", string(criterion))
	}
	if p.Data == "" {
		return []CPE{}, nil
	}

	var ms []CPE
	prev := ""
	for _, item := range splitFS(p.Data, fcSeparator) {
		if item == "" {
			return nil, errors.Errorf("empty entry in packed data. data: %q", p.Data)
		}
		n := int(item[0]) - fcLengthBase
		if n < 0 || n > fcLengthMax {
			return nil, errors.Errorf("unexpected length character. expected: %q..%q, actual: %q", string(rune(fcLengthBase)), string(rune(fcLengthBase+fcLengthMax)), string(item[0]))
		}
		if n > len(prev) {
			return nil, errors.Errorf("shared prefix length exceeds the previous entry. prefix: %d, previous: %q", n, prev)
		}
		if splitsEscape(prev, n) {
			return nil, errors.Errorf("shared prefix ends inside an escape sequence. prefix: %d, previous: %q", n, prev)
		}
		e := prev[:n] + item[1:]
		attrs := splitFS(e, ':')
		for len(attrs) < 8 {
			attrs = append(attrs, "*")
		}
		ms = append(ms, CPE(prefix+strings.Join(attrs, ":")))
		prev = e
	}
	return ms, nil
}

// UnsupportedPackedEncodingError is returned by Unpack for an Encoding
// outside this build's vocabulary: data produced by a newer vuls-data-update
// read by an older binary, or the zero value (unset — a producer-side bug).
// Accept records it as a warning and skips the packed entries rather than
// failing detection; malformed data under a known encoding stays an error.
type UnsupportedPackedEncodingError struct {
	Encoding PackedEncoding
}

func (e *UnsupportedPackedEncodingError) Error() string {
	return fmt.Sprintf("unexpected packed encoding. expected: %q, actual: %q", PackedEncodings(), e.Encoding)
}

// Warning implements warning.Warnable: an unevaluable-packed-encoding
// warning with the offending encoding as the cause.
func (e *UnsupportedPackedEncodingError) Warning() warningTypes.Warning {
	return warningTypes.Warning{Kind: warningTypes.KindUnevaluablePackedEncoding, Cause: string(e.Encoding)}
}

// pvpPrefix returns the "cpe:2.3:<part>:<vendor>:<product>:" prefix of a
// formatted string.
func pvpPrefix(fs string) (string, error) {
	attrs := splitFS(fs, ':')
	if len(attrs) != 13 || attrs[0] != "cpe" || attrs[1] != "2.3" {
		return "", errors.Errorf("unexpected formatted string. expected: %q, actual: %q", "cpe:2.3:<part>:<vendor>:<product>:...", fs)
	}
	return strings.Join(attrs[:5], ":") + ":", nil
}

// splitsEscape reports whether cutting s after its first n bytes separates a
// backslash from the character it escapes, i.e. whether s[:n] ends with an
// escaping (unescaped) backslash.
func splitsEscape(s string, n int) bool {
	escapes := 0
	for i := n - 1; i >= 0 && s[i] == '\\'; i-- {
		escapes++
	}
	return escapes%2 == 1
}

// splitFS splits s on the unescaped occurrences of sep, where a backslash
// escapes the character after it as in a formatted string, leaving the
// escaping of each part untouched so that joining the parts back with sep
// reproduces the input byte for byte. go-cpe is not used here: it only
// unbinds to a WFN, and binding that back yields the canonical formatted
// string, which differs from the input wherever the source leaves a
// character unescaped (NVD writes "12.6(1)_es6" and "rcu_ii+_firmware"; the
// canonical forms escape "(", ")" and "+"). The packed names would then no
// longer match the source's, nor Packable's byte-for-byte prefix check.
func splitFS(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
