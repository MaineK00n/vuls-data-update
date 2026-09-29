// Package ips compares package versions of the Image Packaging System (IPS),
// the package system of Oracle Solaris 11 and the illumos distributions.
//
// An IPS version, as documented in pkg(7) and implemented by
// pkg.version.Version in the reference client (oracle/solaris-ips,
// src/modules/version.py), is
//
//	release[,build_release][-branch][:timestamp]
//
// where release, build_release and branch are dot sequences (non-negative
// integers separated by dots, no negative numbers, no zero padding) and the
// timestamp is an ISO 8601 basic UTC instant, YYYYMMDDThhmmssZ. Only the
// release is mandatory. Examples of what a repository or an installed image
// reports: 0.5.11,5.11-0.175.3.13.0.4.0:20160929T175502Z,
// 11.4-11.4.0.0.1.15.0:20180817T004203Z, 1.8.0.181.12:20180711T215531Z.
//
// Ordering follows pkg(7): release first, then branch, then timestamp;
// build_release never takes part. Dot sequences compare element by element as
// integers (of any size: an element is kept as its decimal digits, which,
// with zero padding rejected, order numerically by length and then by
// digits) and a sequence that is a proper prefix of another sorts before it
// (11.4.94 < 11.4.94.0.1.113.1), which differs from the "missing element is
// zero" reading most version schemes use.
//
// Version.Compare is that order, complete with the reference client's rule
// for a component present on one side only: a missing branch or timestamp
// sorts before any present one (Version.__lt__). That is the right answer for
// choosing the newest package in a repository, but the wrong one for testing
// a version against a pattern, a version that names only the components it
// wants compared, the way "pkg install entire@11.4-11.4.94" names a level
// (pkg(1) calls the whole thing a pkg_fmri_pattern): the pattern would never
// be reached by an installed version that carries a branch it does not name.
// Test is that test, in the spirit of the CONSTRAINT_AUTO matching policy of
// the same client: the pattern decides which components take part, a dot
// sequence it names matches the same depth of the version's, and a component
// it names but the version cannot supply is an error. A pattern that names
// every component in full tests exactly as the order compares.
package ips

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// timestampLayout is the pkg(7) timestamp format, always UTC.
const timestampLayout = "20060102T150405Z"

// Version is a parsed IPS version: what a repository or an installed image
// reports.
type Version struct {
	release      dotSequence
	buildRelease dotSequence // parsed for validation only; pkg(7) ignores it when ordering
	branch       dotSequence // empty when absent
	timestamp    string      // "" when absent; ISO 8601 basic, so string order is time order
}

// dotSequence holds the elements of a pkg(7) dot sequence as their decimal
// digits. parseDotSequence admits only unsigned digits without zero padding,
// so an element orders numerically by its length and then by its digits, with
// no bound on its size (pkg(7) puts none; the reference client uses Python
// integers).
type dotSequence []string

// NewVersion parses an IPS version string. Anything that pkg(7) would reject
// is an error: an empty release, a signalled-but-empty component such as
// "1.0-" or "1.0:", a non-numeric, negative or zero-padded dot sequence
// element, or a timestamp that is not a valid YYYYMMDDThhmmssZ instant. A
// string that is not an IPS version must be a parse error the caller can
// degrade to a non-match, never a silently mis-ordered comparison.
func NewVersion(v string) (Version, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return Version{}, errors.New("version cannot be empty")
	}

	// Cut at the first ':' (timestamp), then the first '-' (branch), then
	// the first ',' (build release), the order pkg.version.Version.__init__
	// looks for them. A second separator is left inside the component that
	// follows it and fails that component's parse, so nothing lax gets in.
	rest, timestamp, hasTimestamp := strings.Cut(s, ":")
	rest, branch, hasBranch := strings.Cut(rest, "-")
	release, buildRelease, hasBuild := strings.Cut(rest, ",")

	if release == "" {
		return Version{}, errors.Errorf("version must have a release value. actual: %q", v)
	}

	var ver Version

	var err error
	if ver.release, err = parseDotSequence(release); err != nil {
		return Version{}, errors.Wrapf(err, "parse release of %q", v)
	}
	if hasBuild {
		if ver.buildRelease, err = parseDotSequence(buildRelease); err != nil {
			return Version{}, errors.Wrapf(err, "parse build_release of %q", v)
		}
	}
	if hasBranch {
		if ver.branch, err = parseDotSequence(branch); err != nil {
			return Version{}, errors.Wrapf(err, "parse branch of %q", v)
		}
	}
	if hasTimestamp {
		t, err := time.Parse(timestampLayout, timestamp)
		if err != nil {
			return Version{}, errors.Wrapf(err, "parse timestamp of %q. expected: %q", v, "YYYYMMDDThhmmssZ")
		}
		// time.Parse accepts a fractional second after the seconds field even
		// when the layout has none, so require the instant to format back to
		// what came in.
		if t.Format(timestampLayout) != timestamp {
			return Version{}, errors.Errorf("parse timestamp of %q. expected: %q, actual: %q", v, "YYYYMMDDThhmmssZ", timestamp)
		}
		// time.Parse takes year 0000; the reference client goes through
		// datetime.datetime, whose years start at 1.
		if t.Year() < 1 {
			return Version{}, errors.Errorf("parse timestamp of %q. year 0000 is not a calendar year", v)
		}
		ver.timestamp = timestamp
	}

	return ver, nil
}

// parseDotSequence keeps the elements as digits, so their size is unbounded
// (pkg(7) puts no bound on an element; the reference client uses Python
// integers). It is stricter than pkg.version.DotSequence, which goes through
// Python int() and so also takes "00" and "+11"; nothing a repository
// publishes looks like that, and rejecting it degrades to a non-match rather
// than a mis-ordering.
func parseDotSequence(s string) (dotSequence, error) {
	elems := strings.Split(s, ".")
	for _, e := range elems {
		if e == "" || (len(e) > 1 && e[0] == '0') || strings.ContainsFunc(e, func(r rune) bool { return r < '0' || r > '9' }) {
			return nil, errors.Errorf("unexpected element. expected: %q, actual: %q", "non-negative integer without zero padding", e)
		}
	}
	return elems, nil
}

// element orders two canonical decimal elements: by length and then by
// digits, since parseDotSequence admits no zero padding. A dot sequence that
// is a proper prefix of another sorts before it (slices.CompareFunc).
func element(a, b string) int {
	return cmp.Or(cmp.Compare(len(a), len(b)), cmp.Compare(a, b))
}

// Compare returns -1 when v sorts before w, 0 when they are the same version,
// and +1 when v sorts after w, under the pkg(7) order: release, then branch,
// then timestamp, build_release ignored, and a branch or timestamp missing on
// one side sorting before a present one (an empty sequence is a prefix of any
// other, and "" is below any timestamp). This is a total order, fit for sort
// or max; for testing a version against a pattern see Test.
func (v Version) Compare(w Version) int {
	return cmp.Or(
		slices.CompareFunc(v.release, w.release, element),
		slices.CompareFunc(v.branch, w.branch, element),
		cmp.Compare(v.timestamp, w.timestamp),
	)
}

// Test compares pattern to the version v with the sign of Version.Compare
// called on the pattern: -1 when the pattern sorts before v, 0 when v is on
// the pattern, +1 when the pattern sorts after v (Test(11.4, 11.3) is +1). It
// is the sign a range endpoint is read with, so a caller checks a "less than
// pattern" bound the way it checks any other type's endpoint. A pattern names
// only the components it wants compared, the way "pkg install
// entire@11.4-11.4.94" names a level rather than a version, so this is a
// match test rather than the order:
//
//   - a component the pattern omits is "don't care" and takes no part;
//   - a dot sequence it names is matched against the same depth of the
//     version's, so the level 11.4-11.4.94 is met by 11.4-11.4.94.0.1.113.1;
//   - a component the pattern names but the version cannot supply cannot be
//     tested and is an error, for the caller to degrade to a non-match.
//
// The error is raised only once the components before it are equal: the
// release alone places "11.3" against the pattern "11.4:20180817T004203Z", so
// the missing timestamp never comes into it. CONSTRAINT_AUTO in the reference
// client matches the same way (DotSequence.is_subsequence for the sequences,
// a component absent from the candidate refusing the match).
func Test(pattern, v Version) (int, error) {
	n, ok := testSequence(pattern.release, v.release)
	switch {
	case n != 0:
		return n, nil
	case !ok:
		return 0, errors.Errorf("the version's release %q does not reach the pattern's %q", strings.Join(v.release, "."), strings.Join(pattern.release, "."))
	}

	// A branch the pattern omits is "don't care"; one it names, the version
	// must supply for the test to go on.
	if len(pattern.branch) != 0 {
		if len(v.branch) == 0 {
			return 0, errors.New("the pattern names a branch the version lacks")
		}
		n, ok := testSequence(pattern.branch, v.branch)
		switch {
		case n != 0:
			return n, nil
		case !ok:
			return 0, errors.Errorf("the version's branch %q does not reach the pattern's %q", strings.Join(v.branch, "."), strings.Join(pattern.branch, "."))
		}
	}

	// Likewise for the timestamp, which the pattern either names in full or
	// not at all.
	if pattern.timestamp != "" {
		if v.timestamp == "" {
			return 0, errors.New("the pattern names a timestamp the version lacks")
		}
		return cmp.Compare(pattern.timestamp, v.timestamp), nil
	}
	return 0, nil
}

// testSequence orders the pattern's dot sequence against the version's, over
// the depth they share. ok is false when the pattern names a deeper level than
// the version reaches, which the shared elements did not already decide.
func testSequence(pattern, v dotSequence) (int, bool) {
	n := min(len(pattern), len(v))
	if c := slices.CompareFunc(pattern[:n], v[:n], element); c != 0 {
		return c, true
	}
	return 0, len(pattern) <= len(v)
}
