package securityreleases

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// Each entry of an advisory names the systems its update is for in
// "Available for". For macOS that field is the affected population stated by
// Apple, which the release name in the section heading does not give: the
// heading names what fixes the issue, so on its own it yields a range with no
// lower end, and on a page that covers several lines at once — "macOS
// Catalina 10.15.7, Security Update 2020-005 High Sierra, Security Update
// 2020-005 Mojave" — only the line whose part carries a version yields
// anything at all. The Security Update parts name no version, so the Mojave
// and High Sierra populations of that page are only in "Available for".
//
// The field is prose and its spelling drifts across two decades:
//
//	macOS Sonoma                                    a line, no version
//	macOS High Sierra 10.13.6                       a version
//	Mac OS X v10.6 through v10.6.6                  a range
//	Mac OS X v10.6.2 or later                       a lower end only
//	Mac OS X Server v10.5.8                         the server edition
//	OS X Lion Server v10.7 to v10.7.5               server between name and version
//	QuickTime 7.1.3 on Mac OS X v10.3.9             a component, then the system
//
// Other families state hardware there — "iPhone 6s and later", "Apple Watch
// Series 6 and later" — which carries no version, so only macOS and Safari
// entries are read.

// macOSLines maps a marketing name to the first version of its line. The
// names are enumerated because the field uses them alone, without a version,
// in more than a third of the macOS entries; every other place in this
// package takes the line from a version instead.
var macOSLines = map[string]string{
	"cheetah": "10.0", "puma": "10.1", "jaguar": "10.2", "panther": "10.3",
	"tiger": "10.4", "leopard": "10.5", "snow leopard": "10.6", "lion": "10.7",
	"mountain lion": "10.8", "mavericks": "10.9", "yosemite": "10.10",
	"el capitan": "10.11", "sierra": "10.12", "high sierra": "10.13",
	"mojave": "10.14", "catalina": "10.15", "big sur": "11", "monterey": "12",
	"ventura": "13", "sonoma": "14", "sequoia": "15", "tahoe": "26",
}

const (
	osWord     = `(?:mac\s?os\s?x|mac\s?os|os\s?x)`
	afVersion  = `(?:v\.?)?(\d+(?:\.\d+)*)(?:\.x)?`
	serverWord = `(?i:^server\b)`
)

var (
	osWordPattern         = regexp.MustCompile(`(?i)` + osWord)
	serverWordPattern     = regexp.MustCompile(`(?i)\bserver\b`)
	osWordAtStart         = regexp.MustCompile(`(?i)^` + osWord + `\b`)
	serverAtStart         = regexp.MustCompile(serverWord)
	afRangePattern        = regexp.MustCompile(`(?i)^` + afVersion + `\s+(?:through|to)\s+(?:` + osWord + `\s+)?(?:server\s+)?` + afVersion)
	afOrLaterPattern      = regexp.MustCompile(`(?i)^` + afVersion + `\s+(?:or|and) later\b`)
	afVersionPattern      = regexp.MustCompile(`^` + afVersion + `(?:\s|$)`)
	availableForSeparator = regexp.MustCompile(`(?i),|\band\b`)
)

// availableFor is one macOS system named in an "Available for" field.
type availableFor struct {
	line    string // first version of the line the entry is about, e.g. "10.13" or "14"
	low     string // stated lower end, empty when the field states no version
	high    string // stated upper end, inclusive; empty when only the fix bounds it
	orLater bool   // "and later", which names every line from low on, not just its own
	server  bool   // the server edition, which has its own CPE and is not extracted
}

// splitAvailableFor cuts a field into the systems it names. "and" separates
// them — "macOS Monterey and macOS Ventura" — but it also opens the
// lower-end form "10.8 and later", where cutting would leave the version
// looking like an upper end and invert the range, so that one is rejoined.
func splitAvailableFor(s string) []string {
	parts := availableForSeparator.Split(s, -1)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(out) > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(part)), "later") {
			out[len(out)-1] += " and " + strings.TrimSpace(part)
			continue
		}
		out = append(out, part)
	}
	return out
}

// parseAvailableFor reads one piece of an "Available for" field. It returns
// nil for a piece that names no macOS system — hardware, Windows, or a bare
// "Mac OS X" with no version at all — and an error for one that names a
// system it cannot read.
func parseAvailableFor(s string) (*availableFor, error) {
	// a stray "Impact:" paragraph is folded into the field on a few 2012
	// pages, so read only up to the first newline
	t := strings.TrimSuffix(strings.TrimSpace(strings.SplitN(s, "\n", 2)[0]), ".")
	loc := osWordPattern.FindStringIndex(t)
	if loc == nil {
		// hardware, Windows, or a family of its own: nothing macOS here
		return nil, nil
	}
	af := availableFor{server: serverWordPattern.MatchString(t)}

	// drop whatever precedes the system name ("QuickTime 7.1.3 on ...") and
	// the system word itself
	body := strings.TrimSpace(osWordAtStart.ReplaceAllString(t[loc[0]:], ""))
	// "Server" sits on either side of the marketing name: "Mac OS X Server
	// v10.5.8" but "OS X Lion Server v10.7.3"
	body = strings.TrimSpace(serverAtStart.ReplaceAllString(body, ""))
	// the names overlap — "sierra" is a prefix of nothing but "lion" is of
	// "lion server" and a suffix of "mountain lion" — so the longest match
	// wins, and a match must end on a word boundary
	var matched string
	for name := range macOSLines {
		if len(name) > len(matched) && hasNamePrefix(body, name) {
			matched = name
		}
	}
	if matched != "" {
		af.line = macOSLines[matched]
		body = strings.TrimSpace(body[len(matched):])
		body = strings.TrimSpace(serverAtStart.ReplaceAllString(body, ""))
	}

	switch {
	case afRangePattern.MatchString(body):
		m := afRangePattern.FindStringSubmatch(body)
		af.low, af.high = m[1], m[2]
	case afOrLaterPattern.MatchString(body):
		af.low, af.orLater = afOrLaterPattern.FindStringSubmatch(body)[1], true
	case afVersionPattern.MatchString(body):
		v := afVersionPattern.FindStringSubmatch(body)[1]
		l := af.line
		if l == "" {
			var err error
			if l, err = lineOf(v); err != nil {
				return nil, err
			}
		}
		// "macOS Catalina 10.15" spells the line out in full, the way
		// "macOS Mojave 10.14.6" names one version of it: Catalina is
		// 10.15. A version equal to the start of its own line therefore
		// names the line and is closed by the fix, not by itself. "10.3.x"
		// arrives here as 10.3 for the same reason, the x standing in for
		// every patch level of the line
		if v == l {
			af.low = v
		} else {
			af.high = v
		}
	case af.line != "":
		// the name alone, which is the whole line and states no version
	case strings.TrimSpace(body) == "":
		// "Mac OS X" with nothing after it names no version at all
		return nil, nil
	default:
		return nil, errors.Errorf("unexpected Available for. expected: a macOS line or version, actual: %q", s)
	}

	if af.line == "" {
		v := af.high
		if v == "" {
			v = af.low
		}
		l, err := lineOf(v)
		if err != nil {
			return nil, err
		}
		af.line = l
	}
	return &af, nil
}

// lineOf reduces a version to the first version of its line: 10.13.6 is
// 10.13, 14.7.5 is 14. The split matches the one recordFix makes, where a
// 10.x minor plays the part a major plays from 11 on.
func lineOf(v string) (string, error) {
	major, rest, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return "", errors.Wrapf(err, "parse major of %q", v)
	}
	if n != 10 {
		return major, nil
	}
	minor, _, _ := strings.Cut(rest, ".")
	if _, err := strconv.Atoi(minor); err != nil {
		return "", errors.Wrapf(err, "parse minor of %q", v)
	}
	return fmt.Sprintf("10.%s", minor), nil
}

// macOSCriterionsFor turns the macOS systems an entry names in "Available
// for" into criterions. What the field states is vulnerable and what the
// section heading states is the fix, so the two ends come from different
// places, and a piece naming a system this does not understand is an error
// rather than a silent drop: more than a third of the macOS entries name
// their line and no version, so the marketing names have to be enumerated,
// and the first advisory for the name after Tahoe would otherwise lose its
// detections without saying so.
func macOSCriterionsFor(availableFors []string, fixesByLine map[string]string) ([]criterionTypes.Criterion, error) {
	var cs []criterionTypes.Criterion
	for _, a := range availableFors {
		for _, part := range splitAvailableFor(a) {
			af, err := parseAvailableFor(part)
			if err != nil {
				return nil, err
			}
			if af == nil || af.server {
				continue
			}
			cpe := macOSCPE
			if strings.HasPrefix(af.line, "10.") {
				cpe = macOSXCPE
			}
			r := ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeApple, GreaterEqual: af.line}
			if af.low != "" {
				r.GreaterEqual = af.low
			}
			fixed := fixesByLine[af.line]
			switch {
			case af.high != "":
				// the update is for the version the field names, so that
				// version is still vulnerable and only le can say so
				r.LessEqual = af.high
			case fixed != "":
				// the heading fixes this very line, and the line stops below it
				r.LessThan = fixed
			case af.orLater:
				// "10.8 and later" on the page of a newer release: the fix
				// ships only in that release, so the older lines stop below
				// it. Only within the same product, a range from mac_os_x
				// into macos being no range at all
				above := highestFixAbove(fixesByLine, af.line)
				if above == "" || strings.HasPrefix(af.line, "10.") != strings.HasPrefix(above, "10.") {
					continue
				}
				fixed = above
				r.LessThan = above
			case af.low != "":
				// a Supplemental Update fixes the named version in place and
				// leaves its number alone, so the version is both ends of it
				r.LessEqual = af.low
			default:
				// naming the line and nothing else, with no fix to close it,
				// would leave the range open at the top
				continue
			}
			c := releaseCriterion(cpe, &r, fixed)
			if !slices.ContainsFunc(cs, func(x criterionTypes.Criterion) bool { return criterionTypes.Compare(x, c) == 0 }) {
				cs = append(cs, c)
			}
		}
	}
	return cs, nil
}

// highestFixAbove returns the newest release the section heading fixes among
// the lines above the given one, empty when the heading fixes none of them.
func highestFixAbove(fixesByLine map[string]string, line string) string {
	var newest string
	for l := range fixesByLine {
		if compareLines(l, line) <= 0 {
			continue
		}
		if newest == "" || compareLines(l, newest) > 0 {
			newest = l
		}
	}
	if newest == "" {
		return ""
	}
	return fixesByLine[newest]
}

// compareLines orders two lines, which are "10.15" up to Catalina and "11"
// from Big Sur on. The 10.x minor plays the part a major plays from 11.
func compareLines(a, b string) int {
	f := func(l string) (int, int) {
		major, rest, _ := strings.Cut(l, ".")
		m, err := strconv.Atoi(major)
		if err != nil {
			return 0, 0
		}
		n, err := strconv.Atoi(rest)
		if err != nil {
			return m, 0
		}
		return m, n
	}
	am, an := f(a)
	bm, bn := f(b)
	if am != bm {
		return cmp.Compare(am, bm)
	}
	return cmp.Compare(an, bn)
}

// hasNamePrefix reports whether body opens with the marketing name, compared
// without case and ending on a word boundary so that "Sierra 10.12.6" is not
// read as the start of "Sierra Nevada".
func hasNamePrefix(body, name string) bool {
	if len(body) < len(name) || !strings.EqualFold(body[:len(name)], name) {
		return false
	}
	if len(body) == len(name) {
		return true
	}
	switch c := body[len(name)]; {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		return false
	default:
		return true
	}
}
