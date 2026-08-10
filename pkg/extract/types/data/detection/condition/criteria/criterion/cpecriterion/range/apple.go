package cpecriterionrange

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// appleVersionPattern matches the version form Apple uses across its
// products: numeric dotted segments optionally followed by a Rapid Security
// Response letter, e.g. "16.5.1" or "16.5.1 (a)".
var appleVersionPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)( \([a-z]\))?$`)

type appleVersion struct {
	segments []int
	rsr      string
}

func newAppleVersion(s string) (appleVersion, error) {
	m := appleVersionPattern.FindStringSubmatch(s)
	if m == nil {
		return appleVersion{}, errors.Errorf("unexpected apple version format. expected: %q, actual: %q", "<major>[.<minor>[...]][ (<rsr letter>)]", s)
	}
	parts := strings.Split(m[1], ".")
	segments := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return appleVersion{}, errors.Wrapf(err, "parse segment %q", p)
		}
		segments = append(segments, n)
	}
	return appleVersion{segments: segments, rsr: m[2]}, nil
}

// Compare orders by the numeric segments (a missing segment counts as 0, so
// 16.4 == 16.4.0), then by the Rapid Security Response letter: an RSR is
// released after the base version it patches, so "" < " (a)" < " (b)" < ...
func (v appleVersion) Compare(u appleVersion) int {
	for i := range max(len(v.segments), len(u.segments)) {
		var a, b int
		if i < len(v.segments) {
			a = v.segments[i]
		}
		if i < len(u.segments) {
			b = u.segments[i]
		}
		if c := cmp.Compare(a, b); c != 0 {
			return c
		}
	}
	return cmp.Compare(v.rsr, u.rsr)
}
