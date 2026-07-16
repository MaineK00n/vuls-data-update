// Package enum orders the extracted-data schema's string enums.
package enum

import (
	"cmp"
	"slices"
)

// Vocabulary is a precomputed view of an enum's known values: the declaration
// order and an O(1) rank index. Build one per enum at package scope so hot
// paths (Sort comparisons, Accept membership guards) neither re-allocate the
// value list nor scan it linearly.
type Vocabulary[T ~string] struct {
	values []T
	rank   map[T]int
}

func NewVocabulary[T ~string](values []T) Vocabulary[T] {
	rank := make(map[T]int, len(values))
	for i, v := range values {
		rank[v] = i
	}
	return Vocabulary[T]{values: values, rank: rank}
}

// Values returns a copy of the vocabulary in declaration order.
func (v Vocabulary[T]) Values() []T {
	return slices.Clone(v.values)
}

// Contains reports whether t is in the vocabulary.
func (v Vocabulary[T]) Contains(t T) bool {
	_, ok := v.rank[t]
	return ok
}

// Compare orders x and y by their position in the vocabulary (declaration
// order). This deliberately preserves the canonical output order from the
// enums' int (iota) era, so converting them to strings does not reorder
// extracted data. Values outside the vocabulary sort after every known
// value — consistent with where an older build places values a newer
// vuls-data-update appended (the vocabularies are append-only) — and
// lexicographically among themselves.
func (v Vocabulary[T]) Compare(x, y T) int {
	xi, xok := v.rank[x]
	yi, yok := v.rank[y]
	switch {
	case xok && yok:
		return cmp.Compare(xi, yi)
	case xok:
		return -1
	case yok:
		return +1
	default:
		return cmp.Compare(x, y)
	}
}
