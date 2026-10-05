package product

import (
	"maps"
	"slices"
)

// Names exposes the product table's names, sorted, for whole-table tests.
func Names() []string {
	return slices.Sorted(maps.Keys(nameToProduct))
}
