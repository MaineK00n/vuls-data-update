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
// integers and a sequence that is a proper prefix of another sorts before it
// (11.4.94 < 11.4.94.0.1.113.1), which differs from the "missing element is
// zero" reading most version schemes use.
//
// Where this package deliberately departs from a strict total order is a
// component present on one side only. pkg(7) orders a missing branch or
// timestamp before any present one; that is the right answer for choosing the
// newest package in a repository, but the wrong one for testing a version
// against a bound: a bound that names only a release, or only a release and a
// timestamp, would then never be reached by an installed version that carries
// a branch. Compare therefore treats a component missing on either side as
// "don't care" and skips it, in the spirit of the CONSTRAINT_AUTO matching
// policy of the same client, so that a bound states exactly the components it
// wants compared.
package ips

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// timestampLayout is the pkg(7) timestamp format, always UTC.
const timestampLayout = "20060102T150405Z"

// Version is a parsed IPS version.
type Version struct {
	release      []int
	buildRelease []int  // parsed for validation only; pkg(7) ignores it when ordering
	branch       []int  // nil when absent
	timestamp    string // "" when absent; ISO 8601 basic, so string order is time order
}

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
		if _, err := time.Parse(timestampLayout, timestamp); err != nil {
			return Version{}, errors.Wrapf(err, "parse timestamp of %q. expected: %q", v, "YYYYMMDDThhmmssZ")
		}
		ver.timestamp = timestamp
	}

	return ver, nil
}

// parseDotSequence mirrors pkg.version.DotSequence: every element is a
// non-negative integer with no zero padding (a lone "0" is fine).
func parseDotSequence(s string) ([]int, error) {
	if s == "" {
		return nil, errors.New("dot sequence cannot be empty")
	}
	elems := strings.Split(s, ".")
	seq := make([]int, 0, len(elems))
	for _, e := range elems {
		if e == "" {
			return nil, errors.Errorf("empty element in %q", s)
		}
		if e[0] == '-' || e[0] == '+' {
			return nil, errors.Errorf("signed element %q in %q", e, s)
		}
		n, err := strconv.Atoi(e)
		if err != nil {
			return nil, errors.Wrapf(err, "parse %q in %q as number", e, s)
		}
		if len(e) > 1 && e[0] == '0' {
			return nil, errors.Errorf("zero padded element %q in %q", e, s)
		}
		seq = append(seq, n)
	}
	return seq, nil
}

// Compare returns -1 when v sorts before w, 0 when they are the same version,
// and +1 when v sorts after w, under the pkg(7) order
// (release, then branch, then timestamp; build_release ignored) with a
// component that is missing on either side skipped as "don't care". See the
// package documentation for why.
//
// Because of the don't-care rule this is not a total order: "11.4" compares
// equal to both "11.4-11.4.1" and "11.4-11.4.94" while those two differ. It
// is meant for testing one version against one bound; do not use it as the
// comparator of sort or max over a mixed set of versions.
func (v Version) Compare(w Version) int {
	return cmp.Or(
		slices.Compare(v.release, w.release),
		compareBranch(v.branch, w.branch),
		compareTimestamp(v.timestamp, w.timestamp),
	)
}

// compareBranch is 0 when either side has no branch (don't care).
func compareBranch(a, b []int) int {
	if a == nil || b == nil {
		return 0
	}
	return slices.Compare(a, b)
}

// compareTimestamp is 0 when either side has no timestamp (don't care).
func compareTimestamp(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	return cmp.Compare(a, b)
}
