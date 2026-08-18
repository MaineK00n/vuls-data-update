// Package apple compares the versions Apple uses across its products.
//
// It sits under internal/version/ alongside whatever other schemes need one
// here. A scheme gets its own package rather than a case in a shared function
// because CompareVersions is handed two version strings and nothing else, so
// the choice of comparator has to be made by the caller's range type.
//
// A version is dotted numeric segments optionally carrying a Rapid Security
// Response letter — 16.5.1, 16.5.1 (a). The letter marks an RSR shipped after
// the base release it patches, so the order is
//
//	16.5.1 < 16.5.1 (a) < 16.5.1 (c) < 16.5.2
//
// and that is the whole reason this exists: the general-purpose comparators
// cannot parse the letter form at all, so a range bounded at an RSR version
// was previously inexpressible. The grammar is shared by every Apple product
// (iOS, iPadOS, macOS, watchOS, tvOS, visionOS, Safari), which is why one
// package covers the vendor.
package apple

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Pattern is the regexp source fragment of a version as it appears in
// Apple's release names: submatch 1 is the dotted numeric version, submatch
// 2 the optional Rapid Security Response letter (" (a)"). It is exported so
// that producers embedding a version inside a larger regexp capture exactly
// what NewVersion accepts, keeping the two in sync by construction.
const Pattern = `([0-9]+(?:\.[0-9]+)*)( \([a-z]\))?`

// pattern is the shape a version has to have. It is deliberately narrow:
// this package is reached from Accept with whatever version a scan reported,
// and a string that is not an Apple version must be a parse error the caller
// can degrade to a non-match, never a silently mis-ordered comparison.
var pattern = regexp.MustCompile(fmt.Sprintf(`^%s$`, Pattern))

// Version is a parsed Apple version.
type Version struct {
	segments []int
	// rsr is the Rapid Security Response letter suffix as matched (" (a)"),
	// and empty when the version carries none. That the base release sorts
	// first is exactly the ordering wanted, so no separate "has a suffix"
	// flag is needed.
	rsr      string
	original string
}

// NewVersion parses an Apple version.
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

	return Version{segments: segments, rsr: m[2], original: v}, nil
}

// Compare returns a negative number when v sorts before w, zero when they
// are the same version, and a positive number otherwise.
//
// Versions of unequal arity compare as though the shorter were zero-padded,
// so 16.4 < 16.4.1 and 16.4 == 16.4.0.
func (v Version) Compare(w Version) int {
	for i := range max(len(v.segments), len(w.segments)) {
		if c := cmp.Compare(segment(v.segments, i), segment(w.segments, i)); c != 0 {
			return c
		}
	}
	return cmp.Compare(v.rsr, w.rsr)
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
