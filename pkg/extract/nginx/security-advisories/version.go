package securityadvisories

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// windowsPrefix marks a vulnerable expression that only applies to the Windows
// build, e.g. "nginx/Windows 0.7.52-1.3.0".
const windowsPrefix = "nginx/Windows "

const (
	allVersions  = "all"
	noneVersions = "none"
)

// nginx releases are always <major>.<minor>.<patch>; anything else is a change
// in how the page expresses versions and must not be guessed at.
var versionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// version is an nginx release. The three components are kept separate because
// the branch a release belongs to (major.minor) is what decides where an
// affected range resumes after a fix — see affectedIntervals.
type version struct {
	major, minor, patch int
}

func parseVersion(s string) (version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return version{}, errors.Errorf("unexpected version format. expected: %q, actual: %q", versionPattern.String(), s)
	}

	// The pattern admits digits only, so the conversions cannot fail short of
	// an integer overflow, which a released nginx version never reaches.
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return version{}, errors.Wrapf(err, "parse major of %q", s)
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return version{}, errors.Wrapf(err, "parse minor of %q", s)
	}
	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return version{}, errors.Wrapf(err, "parse patch of %q", s)
	}

	return version{major: major, minor: minor, patch: patch}, nil
}

func (v version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v version) compare(o version) int {
	if v.major != o.major {
		return v.major - o.major
	}
	if v.minor != o.minor {
		return v.minor - o.minor
	}
	return v.patch - o.patch
}

// nextBranch is the first release of the branch following v's. nginx develops
// stable (even minor) and mainline (odd minor) branches in parallel and fixes
// each separately, so a fix released on one branch says nothing about releases
// on the next one — the affected range resumes there.
func (v version) nextBranch() version {
	return version{major: v.major, minor: v.minor + 1}
}

// interval is one contiguous affected version range. Exactly one of LessThan
// and LessEqual is set. Fixed names the release that closes the interval, i.e.
// the earliest listed fix a user inside the interval can move to.
type interval struct {
	GreaterEqual version
	LessThan     *version
	LessEqual    *version
	Fixed        *version
}

// vulnerableRange is one entry of the page's "Vulnerable:" list.
type vulnerableRange struct {
	// All reports "Vulnerable: all", where no version bound applies.
	All bool
	// Windows reports the "nginx/Windows" prefix: only the Windows build is
	// affected.
	Windows bool
	Lower   version
	Upper   version
}

// parseVulnerable reads one "Vulnerable:" entry. The page writes these as a
// closed range ("0.9.6-1.31.2"), a single release ("1.26.0"), the literal
// "all", and any of those optionally prefixed with "nginx/Windows".
func parseVulnerable(s string) (vulnerableRange, error) {
	if s == allVersions {
		return vulnerableRange{All: true}, nil
	}

	var r vulnerableRange
	if rest, ok := strings.CutPrefix(s, windowsPrefix); ok {
		r.Windows = true
		s = rest
	}

	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		v, err := parseVersion(s)
		if err != nil {
			return vulnerableRange{}, errors.Wrapf(err, "parse vulnerable %q", s)
		}
		r.Lower, r.Upper = v, v
		return r, nil
	}

	l, err := parseVersion(lo)
	if err != nil {
		return vulnerableRange{}, errors.Wrapf(err, "parse lower bound of %q", s)
	}
	u, err := parseVersion(hi)
	if err != nil {
		return vulnerableRange{}, errors.Wrapf(err, "parse upper bound of %q", s)
	}
	if l.compare(u) > 0 {
		return vulnerableRange{}, errors.Errorf("unexpected vulnerable range. expected: %q, actual: %q", "lower bound not above upper bound", s)
	}

	r.Lower, r.Upper = l, u
	return r, nil
}

// parseNotVulnerable reads the "Not vulnerable:" list into the fixed releases it
// names, sorted ascending. Each entry is a release followed by "+" meaning "this
// release and later on its branch"; the literal "none" yields no fix.
func parseNotVulnerable(ss []string) ([]version, error) {
	if len(ss) == 1 && ss[0] == noneVersions {
		return nil, nil
	}

	vs := make([]version, 0, len(ss))
	for _, s := range ss {
		t, ok := strings.CutSuffix(s, "+")
		if !ok {
			return nil, errors.Errorf("unexpected not vulnerable format. expected: %q, actual: %q", "<version>+", s)
		}
		v, err := parseVersion(t)
		if err != nil {
			return nil, errors.Wrapf(err, "parse not vulnerable %q", s)
		}
		vs = append(vs, v)
	}

	slices.SortFunc(vs, version.compare)
	return slices.CompactFunc(vs, func(a, b version) bool { return a.compare(b) == 0 }), nil
}

// affectedIntervals splits a vulnerable range at the fixes that land inside it.
//
// The page states one range spanning every affected branch together with a fix
// per branch, so a fix for an older branch sits in the middle of the range: for
// CVE-2026-42533 ("Vulnerable: 0.9.6-1.31.2", "Not vulnerable: 1.31.3+,
// 1.30.4+") the stable release 1.30.4 is inside 0.9.6-1.31.2 yet not affected.
// Emitting the range verbatim would report those releases as vulnerable, so each
// fix inside the range closes an interval and the next interval resumes at the
// start of the following branch.
//
// This reproduces how NVD splits the same advisories, e.g. CVE-2011-4963
// ("Vulnerable: nginx/Windows 0.7.52-1.3.0", "Not vulnerable: 1.3.1+, 1.2.1+")
// is published as 0.7.52 <= v < 1.2.1 plus 1.3.0.
func affectedIntervals(r vulnerableRange, fixes []version) []interval {
	if r.All {
		return nil
	}

	var is []interval
	cur := r.Lower
	for _, f := range fixes {
		// Fixes at or below the range's start, and those beyond its end, do
		// not split it.
		if f.compare(cur) <= 0 || f.compare(r.Upper) > 0 {
			continue
		}
		lt, fixed := f, f
		is = append(is, interval{GreaterEqual: cur, LessThan: &lt, Fixed: &fixed})
		cur = f.nextBranch()
		if cur.compare(r.Upper) > 0 {
			return is
		}
	}

	return append(is, interval{GreaterEqual: cur, LessEqual: &r.Upper, Fixed: fixedAfter(r.Upper, fixes)})
}

// fixedAfter is the earliest listed fix a user on the interval's last affected
// release can move to. The branch's own fix is preferred implicitly: fixes are
// ascending, so the first one past the bound is the nearest upgrade target.
func fixedAfter(upper version, fixes []version) *version {
	if i := slices.IndexFunc(fixes, func(f version) bool { return f.compare(upper) > 0 }); i >= 0 {
		return &fixes[i]
	}
	return nil
}
