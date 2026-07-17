// Package warning records non-fatal evaluation events on detection results.
//
// The detection types deliberately never log: they record what happened as
// structured data on the result (FilteredCriterion.Warnings), and projecting
// that into logs, scan-result warnings (e.g. vuls0's ScanResult.Warnings) or
// aggregate counts is the caller's job — walk the FilteredCriteria tree and
// group by (Kind, Cause).
package warning

import (
	"cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// Warning is one non-fatal evaluation event. Kind is the machine-readable
// classification; Cause is the concrete datum that triggered it (e.g. the
// enum value this build could not evaluate). Fields may be added append-only;
// existing ones keep their meaning.
type Warning struct {
	Kind  Kind   `json:"kind,omitempty"`
	Cause string `json:"cause,omitempty"`
}

// Kind is a string so that unmarshaling never validates against the known
// set: results produced by a newer build (carrying kinds this build does not
// know) still round-trip losslessly instead of failing the whole read.
type Kind string

const (
	// KindUnevaluableCriterionType: the criterion's Type is outside this
	// build's vocabulary; the criterion was skipped as not affected.
	KindUnevaluableCriterionType Kind = "unevaluable-criterion-type"
	// KindUnevaluablePackageType: the version / none-exist criterion's
	// package Type is outside this build's vocabulary.
	KindUnevaluablePackageType Kind = "unevaluable-package-type"
	// KindUnevaluableRangeType: the affected / cpe range Type is outside
	// this build's vocabulary.
	KindUnevaluableRangeType Kind = "unevaluable-range-type"
)

// Kinds returns every Kind this build knows, in declaration order. The known
// set must be append-only.
func Kinds() []Kind {
	return []Kind{
		KindUnevaluableCriterionType,
		KindUnevaluablePackageType,
		KindUnevaluableRangeType,
	}
}

// Compare orders k against u by vocabulary rank — the declaration order of
// Kinds(). Values outside the vocabulary sort after every known value,
// lexicographically among themselves.
func (k Kind) Compare(u Kind) int {
	return vocabulary.Compare(k, u)
}

var vocabulary = enum.NewVocabulary(Kinds())

func Compare(x, y Warning) int {
	return cmp.Or(
		x.Kind.Compare(y.Kind),
		cmp.Compare(x.Cause, y.Cause),
	)
}
