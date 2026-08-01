package xml

import (
	"regexp"
	"strings"
)

// The "Affects:" line is a comma-separated list of version ranges. Across the
// twelve pages it uses five shapes and two spellings of the same milestone
// suffix, so it is parsed here rather than in the fetcher, which keeps the
// line verbatim.
//
//	Affects: 11.0.0-M1 to 11.0.23                      lower "to" upper
//	Affects: 3.0, 3.1-3.1.1, 3.2-3.2.4, 3.3a-3.3.2     lower "-" upper, and singles
//	Affects: 9.0.0.M1 to 9.0.80                        the dotted milestone spelling
//	Affects: 3.2?, 3.2.1, 3.2.2-3.2.3?                 "?" marks an unverified bound
//	Affects: All versions prior to 1.2.3               open lower bound
//	Affects: Pre-release builds of 4.0.0               no released version affected
//	Affects: JK 1.2.0-1.2.26 (mod_jk only)             product prefix and a qualifier
var (
	// versionPattern is deliberately loose about the tail: Tomcat has shipped
	// 3.3a, 5.0.SVN and 11.0.0-M20 alongside ordinary 11.0.24.
	versionPattern = `[0-9]+(?:\.[0-9A-Za-z]+)*(?:-(?:M|RC)[0-9]+)?`

	rangeToPattern     = regexp.MustCompile(`^(` + versionPattern + `)\?? to (` + versionPattern + `)\??$`)
	rangeDashPattern   = regexp.MustCompile(`^(` + versionPattern + `)\??-(` + versionPattern + `)\??$`)
	singlePattern      = regexp.MustCompile(`^(` + versionPattern + `)\??$`)
	priorToPattern     = regexp.MustCompile(`^All versions prior to (` + versionPattern + `)$`)
	preReleasePattern  = regexp.MustCompile(`^Pre-release builds of (` + versionPattern + `)$`)
	productPrefixRegex = regexp.MustCompile(`^(?:JK|tcnative|OpenSSL|APR) `)
	qualifierPattern   = regexp.MustCompile(`\s*\([^)]*\)$`)

	// dottedMilestonePattern matches the ".M1" / ".RC1" spelling that the 5.x
	// through 9.x pages use where 10.x and 11.x write "-M1" / "-RC1".
	dottedMilestonePattern = regexp.MustCompile(`\.(M|RC)([0-9]+)$`)

	// svnPattern matches the "5.0.SVN" placeholder the 4.1 and 5.0 pages use
	// for a fix that only ever landed on the branch in Subversion. It names no
	// release, so it is not a usable bound.
	svnPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*\.SVN$`)
)

// isRelease reports whether v names a released version, as opposed to the
// "<branch>.SVN" placeholder used for unreleased branch-only fixes.
func isRelease(v string) bool {
	return !svnPattern.MatchString(v)
}

// affected is one version range from an "Affects:" line. An empty Equal means
// the range is bounded by GreaterEqual/LessEqual; an empty GreaterEqual with a
// LessEqual set means every version up to that bound.
type affected struct {
	Equal        string
	GreaterEqual string
	LessEqual    string
}

// parseAffects splits an "Affects:" line into version ranges. Tokens it does
// not recognize are returned separately rather than dropped: the line also
// carries downstream distribution names ("Debian", "Ubuntu and potentially
// other downstream distributions") on entries that are not Tomcat
// vulnerabilities, and the caller decides what to do with them.
func parseAffects(s string) ([]affected, []string) {
	var (
		as      []affected
		unknown []string
	)

	for _, tok := range splitTokens(s) {
		// A trailing qualifier narrows the platform or component rather than
		// the version ("(Windows only)", "(mod_jk only)", "(Memory Realm)").
		// The version range is the same either way, so it is dropped here; the
		// entry's description keeps the wording.
		tok = strings.TrimSpace(qualifierPattern.ReplaceAllString(tok, ""))
		tok = strings.TrimSpace(productPrefixRegex.ReplaceAllString(tok, ""))
		tok = strings.TrimSuffix(tok, ".")
		if tok == "" {
			continue
		}

		// A bound naming no release cannot be compared against, so the whole
		// token is reported as unrecognized rather than half-applied — an
		// upper bound of "5.0.SVN" would otherwise silently become a range
		// that no version can satisfy.
		if strings.Contains(tok, ".SVN") {
			unknown = append(unknown, tok)
			continue
		}

		switch {
		case rangeToPattern.MatchString(tok):
			m := rangeToPattern.FindStringSubmatch(tok)
			as = append(as, affected{GreaterEqual: normalize(m[1]), LessEqual: normalize(m[2])})
		case rangeDashPattern.MatchString(tok):
			m := rangeDashPattern.FindStringSubmatch(tok)
			as = append(as, affected{GreaterEqual: normalize(m[1]), LessEqual: normalize(m[2])})
		case priorToPattern.MatchString(tok):
			m := priorToPattern.FindStringSubmatch(tok)
			as = append(as, affected{LessEqual: normalize(m[1])})
		case preReleasePattern.MatchString(tok):
			// No released version is affected, so there is no range to assert.
			continue
		case singlePattern.MatchString(tok):
			m := singlePattern.FindStringSubmatch(tok)
			as = append(as, affected{Equal: normalize(m[1])})
		default:
			unknown = append(unknown, tok)
		}
	}

	return as, unknown
}

// splitTokens splits on the separators upstream uses between ranges — "," and
// " and " — while leaving the contents of a parenthesized qualifier alone, so
// that "(DataSource and JDBC Realms)" stays with its range.
func splitTokens(s string) []string {
	var (
		out   []string
		cur   strings.Builder
		depth int
	)

	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}

	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '(':
			depth++
			cur.WriteByte(s[i])
		case s[i] == ')':
			depth--
			cur.WriteByte(s[i])
		case s[i] == ',' && depth == 0:
			flush()
		case depth == 0 && strings.HasPrefix(s[i:], " and "):
			flush()
			i += len(" and ") - 1
		default:
			cur.WriteByte(s[i])
		}
	}
	flush()

	return out
}

// normalize rewrites the dotted milestone spelling to the hyphenated one, so
// that "9.0.0.M1" and "10.1.0-M1" are the same shape. Without it the dotted
// form is not a parseable version at all and the range cannot be evaluated.
func normalize(v string) string {
	return dottedMilestonePattern.ReplaceAllString(v, "-$1$2")
}
