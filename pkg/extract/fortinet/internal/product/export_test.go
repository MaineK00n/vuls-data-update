package product

// Exports for the product_test package.

import (
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// ProductEntry is one nameToProduct row, exposed so external tests can assert
// table invariants (the productInfo fields are otherwise unexported).
type ProductEntry struct {
	Name      string
	CPE       string
	RangeType ccRangeTypes.RangeType
}

// ProductEntries returns the product table rows for tests.
func ProductEntries() []ProductEntry {
	es := make([]ProductEntry, 0, len(nameToProduct))
	for name, p := range nameToProduct {
		es = append(es, ProductEntry{Name: name, CPE: p.cpe, RangeType: p.rangeType})
	}
	return es
}
