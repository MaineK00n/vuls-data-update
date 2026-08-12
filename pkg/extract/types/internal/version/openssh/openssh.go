// Package openssh compares OpenSSH release versions.
//
// It sits under internal/version/ alongside whatever other schemes need one
// here. A scheme gets its own package rather than a case in a shared function
// because CompareVersions is handed two version strings and nothing else, so
// the choice of comparator has to be made by the caller's range type.
//
// A release is a dotted number optionally carrying a portable suffix — 9.9,
// 9.9p1, 3.7.1p2. The suffix marks the portable build of that base release,
// which ships after it, so the order is
//
//	9.9 < 9.9p1 < 9.9p2 < 9.10
//
// and that is the whole reason this exists. The general-purpose comparators
// read "p1" as a pre-release and put 9.9p1 *before* 9.9, which inverts every
// bound OpenSSH states in portable versions: an advisory fixed in 9.9p2 and
// affecting up to 9.9p1 would report the release carrying the fix as
// vulnerable. PAN-OS needed its own comparator for the same inversion on "-hN".
//
// Note the last pair above: segments compare numerically, so 9.10 is a later
// release than 9.9 rather than an earlier one.
package openssh

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// pattern is the shape a release has to have. It is deliberately narrow: this
// package is reached from Accept with whatever version a scan reported, and a
// string that is not an OpenSSH release must be a parse error the caller can
// degrade to a non-match, never a silently mis-ordered comparison.
var pattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)(?:[pP]([0-9]+))?$`)

// Version is a parsed OpenSSH release.
type Version struct {
	segments []int
	// portable is the N of the pN suffix, and 0 when the release carries none.
	// That the base release sorts first is exactly the ordering wanted, so no
	// separate "has a suffix" flag is needed.
	portable int
	original string
}

// NewVersion parses an OpenSSH release.
func NewVersion(v string) (Version, error) {
	m := pattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return Version{}, errors.Errorf("unexpected version. expected: %q, actual: %q", pattern.String(), v)
	}

	parts := strings.Split(m[1], ".")
	segments := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, errors.Wrapf(err, "parse %q as number", p)
		}
		segments = append(segments, n)
	}

	var portable int
	if m[2] != "" {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return Version{}, errors.Wrapf(err, "parse %q as number", m[2])
		}
		portable = n
	}

	return Version{segments: segments, portable: portable, original: v}, nil
}

// Compare returns a negative number when v sorts before w, zero when they are
// the same release, and a positive number otherwise.
//
// Releases of unequal arity compare as though the shorter were zero-padded, so
// 3.7 < 3.7.1 and 3.7 == 3.7.0.
func (v Version) Compare(w Version) int {
	for i := range max(len(v.segments), len(w.segments)) {
		if c := cmp.Compare(segment(v.segments, i), segment(w.segments, i)); c != 0 {
			return c
		}
	}
	return cmp.Compare(v.portable, w.portable)
}

// String returns the version as it was given to NewVersion.
func (v Version) String() string {
	return v.original
}

func segment(ss []int, i int) int {
	if i < len(ss) {
		return ss[i]
	}
	return 0
}
