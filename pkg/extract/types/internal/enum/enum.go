// Package enum orders the extracted-data schema's string enums.
package enum

import (
	"cmp"
	"slices"
)

// Compare orders x and y by their position in vocabulary (declaration
// order). This deliberately preserves the canonical output order from the
// enums' int (iota) era, so converting them to strings does not reorder
// extracted data. Values outside the vocabulary sort after every known
// value — consistent with where an older build places values a newer
// vuls-data-update appended (the vocabularies are append-only) — and
// lexicographically among themselves.
func Compare[T ~string](vocabulary []T, x, y T) int {
	xi := slices.Index(vocabulary, x)
	yi := slices.Index(vocabulary, y)
	switch {
	case xi >= 0 && yi >= 0:
		return cmp.Compare(xi, yi)
	case xi >= 0:
		return -1
	case yi >= 0:
		return +1
	default:
		return cmp.Compare(x, y)
	}
}
