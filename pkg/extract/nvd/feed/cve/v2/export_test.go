package v2

import (
	"github.com/hashicorp/go-version"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

// This file re-exports unexported helpers so the external v2_test package can
// exercise the cpematch range logic. It is compiled only under `go test`.

// Bounds mirrors the unexported semverBounds with exported fields, letting
// the external test construct and inspect range bounds.
type Bounds struct{ GE, GT, LE, LT *version.Version }

func (b Bounds) internal() semverBounds {
	return semverBounds{ge: b.GE, gt: b.GT, le: b.LE, lt: b.LT}
}

// ParseRange wraps parseRange, returning the bounds as an exported Bounds.
func ParseRange(match cveTypes.CPEMatch) (Bounds, ccRangeTypes.RangeType) {
	b, rt := parseRange(match)
	return Bounds{GE: b.ge, GT: b.gt, LE: b.le, LT: b.lt}, rt
}

// VersionInBounds wraps versionInBounds.
func VersionInBounds(v *version.Version, b Bounds) bool {
	return versionInBounds(v, b.internal())
}

// UnescapeWFN re-exports unescapeWFN.
var UnescapeWFN = unescapeWFN
