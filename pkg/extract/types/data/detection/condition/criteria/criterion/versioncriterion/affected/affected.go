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
	// Published is set, with Type RangeTypeUnconverted and no Range or Fixed,
	// when the vendor lists the package for the vulnerability but the extractor
	// could not convert its fix into a range: the vendor names the fix only as a
	// link, a release tag, a version without a comparator, or not at all. It
	// records what the vendor published, for a reader of the data; detection does
	// not evaluate it (see Accept).
	Published *Published `json:"published,omitempty"`
}

// Published is the vendor's statement of the fix, as published. None of its
// fields is a version that can be compared.
type Published struct {
	// Fixed is the fixed release as the vendor names it, e.g.
	// "https://aka.ms/OfficeSecurityReleases", "11.0 RC1", "17.10.5.1".
	Fixed string `json:"fixed,omitempty"`
	// Description is the vendor's description of the fix, e.g. "Click to Run",
	// "Release Notes".
	Description string `json:"description,omitempty"`
	// URL is the vendor's link for the fix.
	URL string `json:"url,omitempty"`
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
		ComparePublished(x.Published, y.Published),
	)
}

// ComparePublished orders two Published records, nil first. cpecriterion's
// range.Range carries the same record and orders it with this function.
func ComparePublished(x, y *Published) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil && y != nil:
		return -1
	case x != nil && y == nil:
		return +1
	default:
		return cmp.Or(
			cmp.Compare(x.Fixed, y.Fixed),
			cmp.Compare(x.Description, y.Description),
			cmp.Compare(x.URL, y.URL),
		)
	}
}

// Accept reports whether version v of the package is affected. An Affected of
// Type RangeTypeUnconverted accepts no version and is not evaluated: it is a
// record of a fix the extractor could not convert (see Published), not a
// detection rule, so neither its Published nor any Range beside it is read.
// Published under another Type is ignored as well, and the Range is evaluated as
// usual.
func (a Affected) Accept(family ecosystemTypes.Ecosystem, v string) (bool, error) {
	if a.Type == rangeTypes.RangeTypeUnconverted {
		return false, nil
	}

	for _, r := range a.Range {
		// A Range element with no endpoints expresses nothing — malformed
		// data (no extractor produces one; schema validation is the hard
		// gate) or a newer range type whose constraints live in JSON fields
		// this build's unmarshal drops. Either way the criterion cannot be
		// evaluated: report it as a non-fatal empty-range warning rather
		// than aborting detection in the field. Whether a Type is evaluable
		// is otherwise derived from TestEndpoint (CompareVersions
		// underneath) on the endpoint tests below: anything it has no
		// comparator for (unset, newer-data values, comparator-less
		// vocabulary debt like pacman) answers with
		// *UnsupportedRangeTypeError and is reported as a non-fatal
		// *warning.UnevaluableError.
		if r == (rangeTypes.Range{}) {
			return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}}
		}
		if r.Equal != "" {
			n, err := a.Type.TestEndpoint(family, r.Equal, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
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
			n, err := a.Type.TestEndpoint(family, r.GreaterEqual, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
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
			n, err := a.Type.TestEndpoint(family, r.GreaterThan, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
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
			n, err := a.Type.TestEndpoint(family, r.LessEqual, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
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
			n, err := a.Type.TestEndpoint(family, r.LessThan, v)
			if err != nil {
				if w, ok := stderrors.AsType[warningTypes.Warnable](err); ok {
					return false, &warningTypes.UnevaluableError{Warning: w.Warning(), Err: err}
				}
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
