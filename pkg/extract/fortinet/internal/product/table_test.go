package product

import (
	"testing"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// A product's comparator is per-CPE, so every name sharing a CPE must map it to
// the same range type. A table edit that gives one CPE conflicting range types
// would silently mis-compare at detect time, so guard the invariant here.
func TestNameToProductCPERangeTypeConsistent(t *testing.T) {
	type entry struct {
		rangeType ccRangeTypes.RangeType
		name      string
	}
	byCPE := make(map[string]entry, len(nameToProduct))
	for name, p := range nameToProduct {
		if e, ok := byCPE[p.cpe]; ok {
			if e.rangeType != p.rangeType {
				t.Errorf("cpe %q has conflicting range types: %s (product %q) and %s (product %q)", p.cpe, e.rangeType, e.name, p.rangeType, name)
			}
			continue
		}
		byCPE[p.cpe] = entry{rangeType: p.rangeType, name: name}
	}
}
