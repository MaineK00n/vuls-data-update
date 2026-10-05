package product

import (
	"maps"
	"slices"
)

// Names exposes the product table's names, sorted, for whole-table tests.
func Names() []string {
	return slices.Sorted(maps.Keys(nameToProduct))
}

// CPEs exposes a product's CNA and NVD CPEs apart, for whole-table tests.
func CPEs(name string) (cna, nvd []string) {
	p := nameToProduct[name]
	return p.cna, p.nvd
}
