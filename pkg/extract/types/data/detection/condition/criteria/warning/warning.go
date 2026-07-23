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
	"fmt"

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
	// KindEmptyRange: a Range with no endpoints, which expresses nothing —
	// malformed data (schema validation's hard gate) or a newer range type
	// whose constraints live in JSON fields this build's unmarshal drops.
	// The criterion is skipped. It carries no Cause: the trigger is the
	// absence of endpoints, not any concrete datum, and the range type is
	// already reachable from the criterion the warning attaches to.
	KindEmptyRange Kind = "empty-range"
)

// Kinds returns every Kind this build knows, in declaration order. The known
// set must be append-only.
func Kinds() []Kind {
	return []Kind{
		KindUnevaluableCriterionType,
		KindUnevaluablePackageType,
		KindUnevaluableRangeType,
		KindEmptyRange,
	}
}

// Compare orders k against u by vocabulary rank — the declaration order of
// Kinds(). Values outside the vocabulary sort after every known value,
// lexicographically among themselves.
func (k Kind) Compare(u Kind) int {
	return vocabulary.Compare(k, u)
}

var vocabulary = enum.NewVocabulary(Kinds())

// UnevaluableError is returned (in place of a silent skip) by the layer that
// discovers it cannot evaluate its own data — e.g. package.Accept on an
// out-of-vocabulary PackageType — carrying the Warning to record. It is
// non-fatal by contract: criterion.Accept catches it with errors.As,
// accumulates the Warning on the FilteredCriterion, and treats the query as
// not accepted. Only the layer that owns the data inspects it; intermediate
// layers just propagate (wrapping is fine, errors.As traverses).
type UnevaluableError struct {
	Warning Warning
}

func (e *UnevaluableError) Error() string {
	if e.Warning.Cause == "" {
		return fmt.Sprintf("unevaluable: %s", e.Warning.Kind)
	}
	return fmt.Sprintf("unevaluable: %s %q", e.Warning.Kind, e.Warning.Cause)
}

func Compare(x, y Warning) int {
	return cmp.Or(
		x.Kind.Compare(y.Kind),
		cmp.Compare(x.Cause, y.Cause),
	)
}
