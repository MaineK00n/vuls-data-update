package affected

import (
	"cmp"
	stderrors "errors"
	"slices"

	"github.com/pkg/errors"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Affected struct {
	Type  rangeTypes.RangeType `json:"type,omitempty"`
	Range []rangeTypes.Range   `json:"range,omitempty"`
	Fixed []string             `json:"fixed,omitempty"`
}

func (a *Affected) Sort() {
	slices.SortFunc(a.Range, rangeTypes.Compare)
	slices.Sort(a.Fixed)
}

func Compare(x, y Affected) int {
	return cmp.Or(
		x.Type.Compare(y.Type),
		slices.CompareFunc(x.Range, y.Range, rangeTypes.Compare),
		slices.Compare(x.Fixed, y.Fixed),
	)
}

func (a Affected) Accept(family ecosystemTypes.Ecosystem, v string) (bool, error) {
	// The declared Unknown vocabulary value is normal data ("the source
	// declared a constraint we could not translate", not "no constraint")
	// and quietly refuses to match — this also closes the all-empty-Range
	// match-all path below, mirroring cpecriterion/range.
	if a.Type == rangeTypes.RangeTypeUnknown {
		return false, nil
	}
	// Types outside the vocabulary — unset, or data from a newer
	// vuls-data-update — are refused wholesale as unevaluable, reported as a
	// non-fatal *warning.UnevaluableError for the criterion layer to record.
	// Bounded ranges would degrade to false on their own via *CompareError,
	// but an all-empty Range element never calls CompareVersions, and for an
	// unknown type "all-empty" cannot be trusted: a newer type may carry
	// constraints in JSON fields this build's unmarshal silently drops, so
	// matching every version would risk false positives.
	if !a.Type.Known() {
		return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(a.Type)}}
	}
	// Comparator-less vocabulary debt (pacman, freebsd-pkg) degrades
	// silently by policy — bounded ranges already do, via CompareError — but
	// it must not fall through to the all-empty-Range match-all below: a
	// type that can evaluate nothing must not match everything.
	if !a.Type.Evaluable() {
		return false, nil
	}
	for _, r := range a.Range {
		if r.Equal != "" {
			n, err := a.Type.CompareVersions(family, r.Equal, v)
			if err != nil {
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.Equal, v)
			}
			if n != 0 {
				continue
			}
		}
		if r.GreaterEqual != "" {
			n, err := a.Type.CompareVersions(family, r.GreaterEqual, v)
			if err != nil {
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterEqual, v)
			}
			if n > 0 {
				continue
			}
		}
		if r.GreaterThan != "" {
			n, err := a.Type.CompareVersions(family, r.GreaterThan, v)
			if err != nil {
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.GreaterThan, v)
			}
			if n >= 0 {
				continue
			}
		}
		if r.LessEqual != "" {
			n, err := a.Type.CompareVersions(family, r.LessEqual, v)
			if err != nil {
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessEqual, v)
			}
			if n < 0 {
				continue
			}
		}
		if r.LessThan != "" {
			n, err := a.Type.CompareVersions(family, r.LessThan, v)
			if err != nil {
				if _, ok := stderrors.AsType[*rangeTypes.CompareError](err); ok {
					continue
				}
				return false, errors.Wrapf(err, "compare (type: %s, v1: %s, v2: %s)", a.Type, r.LessThan, v)
			}
			if n <= 0 {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}
