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
// Version.Truncate makes that test the order's business: it cuts a version
// down to the shape of the pattern (a component the pattern omits is dropped,
// a dot sequence it names is cut to the same depth), after which the two have
// the same shape and Compare is the level match, in the spirit of the
// CONSTRAINT_AUTO matching policy of the same client. A component the pattern
// names but the version cannot supply is an error, for the caller to degrade
// to a non-match. A pattern that names every component in full leaves the
// version as it is.
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

// String is v in the pkg(7) grammar, release[,build_release][-branch][:timestamp]:
// what NewVersion parsed, without the surrounding whitespace it tolerates, so
// NewVersion(v.String()) is v again.
func (v Version) String() string {
	var b strings.Builder
	b.WriteString(strings.Join(v.release, "."))
	if len(v.buildRelease) != 0 {
		b.WriteString(",")
		b.WriteString(strings.Join(v.buildRelease, "."))
	}
	if len(v.branch) != 0 {
		b.WriteString("-")
		b.WriteString(strings.Join(v.branch, "."))
	}
	if v.timestamp != "" {
		b.WriteString(":")
		b.WriteString(v.timestamp)
	}
	return b.String()
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
// or max; a version is put against a pattern by cutting it to the pattern's
// shape with Truncate first.
func (v Version) Compare(w Version) int {
	return cmp.Or(
		slices.CompareFunc(v.release, w.release, element),
		slices.CompareFunc(v.branch, w.branch, element),
		cmp.Compare(v.timestamp, w.timestamp),
	)
}

// Truncate returns v cut down to the components shape names: one shape omits
// is dropped, a dot sequence shape names is cut to the same depth, and the
// timestamp is kept when shape has one. It is an error when v cannot supply a
// component, because it has none or its dot sequence is shallower than the
// one shape names, for the caller to degrade to a non-match. build_release is
// always dropped, since pkg(7) ignores it when ordering.
//
// The result has exactly the shape of shape, so Compare between the two has
// no missing component left to order and reads as the level match: the level
// 11.4-11.4.94 is met by 11.4-11.4.94.0.1.113.1 (as "pkg install
// entire@11.4-11.4.94" reads it), and "11.3" cannot be cut to the shape of
// 11.4-11.4.94 at all, whatever its release says. CONSTRAINT_AUTO in the
// reference client refuses a candidate in the same way (a component the
// pattern names and the candidate lacks fails the match before any ordering).
func (v Version) Truncate(shape Version) (Version, error) {
	var t Version

	var err error
	if t.release, err = truncateSequence(v.release, shape.release); err != nil {
		return Version{}, errors.Wrap(err, "truncate release")
	}

	if len(shape.branch) != 0 {
		if len(v.branch) == 0 {
			return Version{}, errors.New("the shape names a branch the version lacks")
		}
		if t.branch, err = truncateSequence(v.branch, shape.branch); err != nil {
			return Version{}, errors.Wrap(err, "truncate branch")
		}
	}

	if shape.timestamp != "" {
		if v.timestamp == "" {
			return Version{}, errors.New("the shape names a timestamp the version lacks")
		}
		t.timestamp = v.timestamp
	}

	return t, nil
}

// truncateSequence cuts v to the depth of shape, or fails when v does not
// reach it.
func truncateSequence(v, shape dotSequence) (dotSequence, error) {
	if len(shape) > len(v) {
		return nil, errors.Errorf("%q does not reach the depth of %q", strings.Join(v, "."), strings.Join(shape, "."))
	}
	return v[:len(shape)], nil
}
