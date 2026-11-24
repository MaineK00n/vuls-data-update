// Package product resolves Fortinet product names (shared between the CSAF and
// CVRF extractors) to CPEs and their per-product range types.
package product

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	nonnumericVersion "github.com/vulsio/go-fortinet-version/nonnumeric"
	numericVersion "github.com/vulsio/go-fortinet-version/numeric"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// Resolve returns the CPE 2.3 formatted strings (wildcard version) a host
// running a Fortinet product may be recorded under — the CPEs Fortinet assigns
// as CNA first, then the ones this table published before, none repeated —
// and the product's cpecriterion range type, or ok=false when the name is not
// in the table. A detection matches a host recorded under any of the CPEs.
// Fortinet uses one range type per product, so a product whose versioning
// scheme later diverges gets its own comparator without affecting any other
// product.
func Resolve(name string) (cpes []string, rangeType ccRangeTypes.RangeType, ok bool) {
	p, ok := nameToProduct[strings.TrimSpace(name)]
	return slices.Concat(p.cna, p.nvd), p.rangeType, ok
}

// versionEscaper escapes the CPE WFN special characters (dots and hyphens) in a
// concrete version string. It is stateless and safe for concurrent use, so it
// is shared rather than rebuilt on every BakeVersion call.
var versionEscaper = strings.NewReplacer(".", `\.`, "-", `\-`)

// BakeVersion returns cpe with its version attribute set to the concrete
// version string (dots/hyphens escaped per CPE WFN rules), e.g.
// ("cpe:2.3:o:fortinet:fortios:*:...", "7.4.3") -> the same CPE pinned to
// 7.4.3. Mirrors go-cve-dictionary's fetcher/fortinet version handling.
func BakeVersion(cpe, version string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	if err := wfn.Set(common.AttributeVersion, versionEscaper.Replace(version)); err != nil {
		return "", errors.Wrapf(err, "set version %q", version)
	}
	return naming.BindToFS(wfn), nil
}

// IsExactVersion reports whether ver is a concrete, enumerable release of the
// named product rather than a coarse release train. Most Fortinet products cut
// releases with three or more dot-separated components (e.g. FortiOS "7.4.3",
// FortiSASE "25.2.a"), so a one- or two-component token ("7", "7.4") is a
// train. A few products version their releases with two components (e.g.
// FortiAuthenticator OutlookAgent "2.1", IPS Engine "7.166"); those are marked
// twoComponentVersions in the table (see its comment for the evidence bar),
// and for them a two-component token is a concrete release — only a bare major
// is a train. The distinction cannot be made from the version string alone:
// the same "X.Y" shape is an exact IPS Engine build but a FortiOS train. An
// unknown product name falls back to the three-component rule.
func IsExactVersion(name, ver string) bool {
	if nameToProduct[strings.TrimSpace(name)].twoComponentVersions {
		return strings.Count(ver, ".") >= 1
	}
	return strings.Count(ver, ".") >= 2
}

// NonNumericVersioned reports whether products of range type rt version their
// releases with Fortinet's non-numeric (milestone-letter) scheme ("25.2.a"),
// the range types cpecriterion/range CompareVersions serves with the
// non-numeric comparator. Every check the extractors make for such a product
// (train-granular bounds, a milestone read as its train, the scheme a
// concrete version must parse under) asks here, so they cannot disagree on
// which products they cover.
func NonNumericVersioned(rt ccRangeTypes.RangeType) bool {
	switch rt {
	case ccRangeTypes.RangeTypeFortinetFortiSASE, ccRangeTypes.RangeTypeFortinetFortiSASESovereign:
		return true
	default:
		return false
	}
}

// ValidateVersion returns an error unless ver, a concrete version to bake
// into a CPE of range type rt, parses under the scheme the detector compares
// that range type's versions with: the non-numeric (milestone-letter) one for
// a NonNumericVersioned range type ("25.2.a"), Fortinet's numeric one for any
// other. BakeVersion accepts many CPE-legal shapes no scanner reports
// ("7.0.x", "v7.0.0", "7..0"); one baked would be a criterion nothing
// matches, a silent detection false negative, so the extractors bake only a
// version that passes.
func ValidateVersion(rt ccRangeTypes.RangeType, ver string) error {
	if NonNumericVersioned(rt) {
		if _, err := nonnumericVersion.NewVersion(ver); err != nil {
			return errors.Wrapf(err, "parse %q under the non-numeric scheme", ver)
		}
		return nil
	}
	if _, err := numericVersion.NewVersion(ver); err != nil {
		return errors.Wrapf(err, "parse %q under the numeric scheme", ver)
	}
	return nil
}

// respellings maps a misspelling Fortinet's advisories give a release of a
// non-numeric-versioned product to the spelling its release notes give it,
// each written for the one shape it was seen in. The release notes join
// every component with a dot (the FortiSASE 7.4 Release Notes: "26.3.1.a",
// "25.4.b.1"), which is what the non-numeric comparator parses and how a
// scanner reports the release; the advisories' spellings parse under no
// scheme.
var respellings = []struct {
	pattern *regexp.Regexp
	repl    string
}{
	// A hotfix of a numeric release, its letter joined by "_": "26.3.1_a" for
	// 26.3.1.a (the CVRF of FG-IR-26-267 to 270, also 26.2.1_a; the CSAF of
	// FG-IR-26-267 to 269).
	{pattern: regexp.MustCompile(`^(\d+\.\d+\.\d+)_([a-z])$`), repl: "$1.$2"},
	// A maintenance release of a milestone, its number joined to the letter:
	// "24.4.b1" for 24.4.b.1 (the CVRF of FG-IR-26-154 and 270). One digit,
	// as every such number in the release notes has (25.1.a.1 to 25.4.c.1);
	// a longer run ("25.1.a10") is not read.
	{pattern: regexp.MustCompile(`^(\d+\.\d+\.[a-z])(\d)$`), repl: "$1.$2"},
}

// NormalizeVersion returns ver, a concrete release of a product of range type
// rt as an advisory spells it, in the spelling of Fortinet's release notes
// (see respellings), the one rt's comparator parses and a scanner reports.
// Only the releases of a NonNumericVersioned range type are respelled. Any
// other ver is returned as given, for the caller to validate
// (ValidateVersion), so a misspelling not seen before fails the extract
// rather than being guessed at.
func NormalizeVersion(rt ccRangeTypes.RangeType, ver string) string {
	if !NonNumericVersioned(rt) {
		return ver
	}
	for _, r := range respellings {
		if r.pattern.MatchString(ver) {
			return r.pattern.ReplaceAllString(ver, r.repl)
		}
	}
	return ver
}

// TrainRange builds a range spanning an entire release train of the named
// product: ge train, lt <next train>, where <next> increments the train's
// last numeric component (7.0 -> 7.1, 7 -> 8). It errors when the input is a
// concrete release of that product rather than a train (IsExactVersion — for
// a twoComponentVersions product even "7.166" is concrete), or when the last
// component is not numeric. The Range Type is left unset; the caller sets the
// per-product range type.
func TrainRange(name, train string) (ccRangeTypes.Range, error) {
	// Spanning a concrete release would silently narrow the range ("7.0.0" ->
	// [7.0.0, 7.0.1) instead of the 7.0 train; IPS Engine "7.166" -> [7.166,
	// 7.167) instead of the single build) — a detection false negative or a
	// bogus range, so reject it as unexpected input.
	if IsExactVersion(name, train) {
		return ccRangeTypes.Range{}, errors.Errorf("expected a release train of %q, got concrete version %q", name, train)
	}
	ss := strings.Split(train, ".")
	last, err := strconv.Atoi(ss[len(ss)-1])
	if err != nil {
		return ccRangeTypes.Range{}, errors.Wrapf(err, "non-numeric train %q", train)
	}
	ss[len(ss)-1] = strconv.Itoa(last + 1)
	return ccRangeTypes.Range{
		GreaterEqual: train,
		LessThan:     strings.Join(ss, "."),
	}, nil
}
