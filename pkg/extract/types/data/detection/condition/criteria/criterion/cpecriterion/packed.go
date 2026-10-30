package cpecriterion

import (
	"cmp"
	"fmt"
	"iter"
	"slices"
	"strings"
	"unicode/utf8"

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
	// followed by the remainder; entries are joined with a space. The length
	// character is the length plus '0', so "0".."9" read as themselves and
	// ":".."[" continue to 43, the cap; a longer shared prefix is cut at 43
	// and the rest is written out. The prefix never ends inside a multi-byte
	// UTF-8 sequence, so the text stays valid UTF-8. '"' and '\' never occur
	// as length characters, so the text needs no escaping in JSON. A space
	// is not a character of a WFN attribute value, quoted or not (NISTIR
	// 7695 §5.3.2 allows letters, digits, "_" and quoted punctuation only),
	// so it never occurs in a formatted string and is an unambiguous
	// separator: a name may hold any other byte, "|" included.
	//
	//	entries 10.0.0, 10.0.1, 10.0.2  →  "010.0.0 51 52"
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
	fcSeparator  = ' '
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
// shares the criterion's part, vendor and product byte for byte, has exactly
// eight attributes after them, split as a formatted string is (a backslash
// quoting the character after it), and does not end in an unquoted
// backslash, which quotes nothing. A criterion whose product is a wildcard,
// for example, enumerates concrete products that do not share it; a name
// go-cpe accepts by reading a colon after a quoted backslash ("\\:") as
// quoted has more than eight. Such an entry belongs in CPEMatches, where the
// whole name is kept. Packable is the gate the extractor uses; PackCPEMatches
// rejects the same names, as a backstop, and Unpack rejects what they do.
func Packable(criterion, m CPE) bool {
	prefix, err := pvpPrefix(string(criterion))
	if err != nil {
		return false
	}
	rest, ok := strings.CutPrefix(string(m), prefix)
	return ok && len(splitFS(rest, ':')) == 8 && !endsInEscape(rest)
}

// PackCPEMatches encodes matches, which must all be Packable against
// criterion, as PackedEncodingFC. Each entry is reduced to its attributes
// after the product with the trailing "*" attributes after the version
// dropped ("cpe:2.3:a:v:p:12.0:beta1:*:*:*:*:*:*" becomes "12.0:beta1",
// "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*" becomes "*"; escaping is left as is), then
// the reduced strings are sorted, deduplicated and front-coded. An entry
// that is not Packable is an error, as is one holding the separator, which
// no formatted string does (see PackedEncodingFC).
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
		if strings.IndexByte(rest, fcSeparator) >= 0 {
			return nil, errors.Errorf("unexpected %q in a formatted string. match: %q", fcSeparator, string(m))
		}
		if endsInEscape(rest) {
			return nil, errors.Errorf("unexpected unquoted backslash at the end of a formatted string. match: %q", string(m))
		}
		for len(attrs) > 1 && attrs[len(attrs)-1] == "*" {
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
		// Never cut inside a multi-byte UTF-8 sequence (whether the entries
		// diverge there or the cap falls there): the text would then hold
		// a bare continuation byte and no longer be valid UTF-8. Cutting
		// between a backslash and the character it quotes is harmless, as
		// the separator never occurs in a name.
		for n > 0 && n < len(e) && !utf8.RuneStart(e[n]) {
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
// names come back sorted by their reduced form. A nil p, or the zero value,
// holds no packed set and gives nil; a zero Encoding with Data is an error,
// as is any other malformed Data under a known encoding. Data is taken to be
// valid UTF-8, as a string decoded from JSON is.
func (p *CPEMatchesPacked) Unpack(criterion CPE) ([]CPE, error) {
	if p == nil {
		return nil, nil
	}
	switch p.Encoding {
	case "":
		if p.Data == "" {
			return nil, nil
		}
		return nil, errors.Errorf("unexpected packed data without an encoding. data: %q", p.Data)
	case PackedEncodingFC:
	default:
		return nil, &UnsupportedPackedEncodingError{Encoding: p.Encoding}
	}
	prefix, err := pvpPrefix(string(criterion))
	if err != nil {
		return nil, errors.Wrapf(err, "pvp prefix of %q", string(criterion))
	}

	ms := []CPE{}
	for e, err := range p.reduced() {
		if err != nil {
			return nil, err
		}
		// unbindReduced applies the same two checks on the matching path;
		// go-cpe panics on a name ending in an unquoted backslash.
		if endsInEscape(e) {
			return nil, errors.Errorf("entry ends with an unquoted backslash. entry: %q", e)
		}
		if n := len(splitFS(string(e), ':')); n > 8 {
			return nil, errors.Errorf("unexpected number of attributes after the product. expected: at most 8, actual: %d, entry: %q", n, e)
		}
		ms = append(ms, fullName(prefix, e))
	}
	return ms, nil
}

// fullName restores the formatted string of an entry from its reduced form
// and the criterion's "cpe:2.3:part:vendor:product:" prefix.
func fullName(prefix string, e []byte) CPE {
	attrs := splitFS(string(e), ':')
	for len(attrs) < 8 {
		attrs = append(attrs, "*")
	}
	return CPE(prefix + strings.Join(attrs, ":"))
}

// reduced decodes the front coding, yielding each entry in its reduced form
// in order, or the error decoding stopped at. Encoding must be
// PackedEncodingFC; the caller checks. The entries are built in one buffer,
// each on the shared prefix of the one before, and the yielded slice is
// that buffer: it is valid during the yield only, and a caller that keeps
// anything of it copies it (Unpack restores a new string from it; Accept
// relates it to the query and moves on).
func (p *CPEMatchesPacked) reduced() iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		if p.Data == "" {
			return
		}
		var prev []byte
		for item := range strings.SplitSeq(p.Data, string(fcSeparator)) {
			if item == "" {
				yield(nil, errors.Errorf("empty entry in packed data. data: %q", p.Data))
				return
			}
			n := int(item[0]) - fcLengthBase
			if n < 0 || n > fcLengthMax {
				yield(nil, errors.Errorf("unexpected length character. expected: %q..%q, actual: %q", string(rune(fcLengthBase)), string(rune(fcLengthBase+fcLengthMax)), string(item[0])))
				return
			}
			if n > len(prev) {
				yield(nil, errors.Errorf("shared prefix length exceeds the previous entry. prefix: %d, previous: %q", n, prev))
				return
			}
			if n < len(prev) && !utf8.RuneStart(prev[n]) {
				yield(nil, errors.Errorf("shared prefix ends inside a UTF-8 sequence. prefix: %d, previous: %q", n, prev))
				return
			}
			prev = append(prev[:n], item[1:]...)
			if len(prev) == 0 {
				yield(nil, errors.Errorf("empty reduced entry in packed data. data: %q", p.Data))
				return
			}
			if !yield(prev, nil) {
				return
			}
		}
	}
}

// UnsupportedPackedEncodingError is returned by Unpack for an Encoding
// outside this build's vocabulary: data produced by a newer vuls-data-update
// read by an older binary. Accept records it as a warning and skips the
// packed entries rather than failing detection; malformed data under a known
// encoding, and Data under an empty Encoding, stay errors.
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

// endsInEscape reports whether s ends with an unquoted backslash, one that
// would quote the character after it: an odd run of trailing backslashes.
func endsInEscape[S ~string | ~[]byte](s S) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
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
	return slices.Collect(splitFSSeq(s, sep))
}

// splitFSSeq is splitFS as an iterator.
func splitFSSeq(s string, sep byte) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case sep:
				if !yield(s[start:i]) {
					return
				}
				start = i + 1
			}
		}
		yield(s[start:])
	}
}
