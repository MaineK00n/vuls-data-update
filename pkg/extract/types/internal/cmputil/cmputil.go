// Package cmputil provides small comparison helpers for the extracted-data
// schema's Compare functions.
package cmputil

// Ptr orders two pointers nil-first and otherwise applies compare to the
// pointed-to values. Compare functions use it to keep their ordering total
// over every field this build can see — in particular in type-dispatch
// default branches, where an out-of-vocabulary type (data from a newer
// vuls-data-update) cannot select a payload arm but the canonical order must
// remain deterministic under the unstable slices.SortFunc.
func Ptr[T any](x, y *T, compare func(T, T) int) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return +1
	default:
		return compare(*x, *y)
	}
}
