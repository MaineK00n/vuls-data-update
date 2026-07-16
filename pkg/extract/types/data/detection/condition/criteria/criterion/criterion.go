package criterion

import (
	"cmp"

	"github.com/pkg/errors"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// CriterionType is a string so that unmarshaling never validates against the
// known set: data produced by a newer vuls-data-update (carrying criterion
// types this build does not know) still round-trips losslessly instead of
// failing the whole read.
type CriterionType string

const (
	CriterionTypeVersion   CriterionType = "version"
	CriterionTypeNoneExist CriterionType = "none-exist"
	CriterionTypeKB        CriterionType = "kb"
	CriterionTypeCPE       CriterionType = "cpe"

	CriterionTypeUnknown CriterionType = "unknown"
)

// CriterionTypes returns every CriterionType this build knows, in declaration
// order. Consumers (vuls2, vuls0) diff this list against a newer
// vuls-data-update in CI to detect enum additions that require a dependency
// bump. The known set must be append-only.
func CriterionTypes() []CriterionType {
	return []CriterionType{
		CriterionTypeVersion,
		CriterionTypeNoneExist,
		CriterionTypeKB,
		CriterionTypeCPE,
		CriterionTypeUnknown,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// CriterionTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t CriterionType) Compare(u CriterionType) int {
	return vocabulary.Compare(t, u)
}

var vocabulary = enum.NewVocabulary(CriterionTypes())

type Criterion struct {
	Type      CriterionType       `json:"type,omitempty"`
	Version   *vcTypes.Criterion  `json:"version,omitempty"`
	NoneExist *necTypes.Criterion `json:"none_exist,omitempty"`
	KB        *kbcTypes.Criterion `json:"kb,omitempty"`
	CPE       *ccTypes.Criterion  `json:"cpe,omitempty"`
}

func (c *Criterion) Sort() {
	switch c.Type {
	case CriterionTypeVersion:
		if c.Version != nil {
			c.Version.Sort()
		}
	case CriterionTypeNoneExist:
		if c.NoneExist != nil {
			c.NoneExist.Sort()
		}
	case CriterionTypeKB:
		if c.KB != nil {
			c.KB.Sort()
		}
	case CriterionTypeCPE:
		if c.CPE != nil {
			c.CPE.Sort()
		}
	default:
	}
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		x.Type.Compare(y.Type),
		func() int {
			switch x.Type {
			case CriterionTypeVersion:
				switch {
				case x.Version == nil && y.Version == nil:
					return 0
				case x.Version == nil && y.Version != nil:
					return -1
				case x.Version != nil && y.Version == nil:
					return +1
				default:
					return vcTypes.Compare(*x.Version, *y.Version)
				}
			case CriterionTypeNoneExist:
				switch {
				case x.NoneExist == nil && y.NoneExist == nil:
					return 0
				case x.NoneExist == nil && y.NoneExist != nil:
					return -1
				case x.NoneExist != nil && y.NoneExist == nil:
					return +1
				default:
					return necTypes.Compare(*x.NoneExist, *y.NoneExist)
				}
			case CriterionTypeKB:
				switch {
				case x.KB == nil && y.KB == nil:
					return 0
				case x.KB == nil && y.KB != nil:
					return -1
				case x.KB != nil && y.KB == nil:
					return +1
				default:
					return kbcTypes.Compare(*x.KB, *y.KB)
				}
			case CriterionTypeCPE:
				switch {
				case x.CPE == nil && y.CPE == nil:
					return 0
				case x.CPE == nil && y.CPE != nil:
					return -1
				case x.CPE != nil && y.CPE == nil:
					return +1
				default:
					return ccTypes.Compare(*x.CPE, *y.CPE)
				}
			default:
				return 0
			}
		}(),
	)
}

type Query struct {
	Version   []vcTypes.Query
	NoneExist *necTypes.Query
	KB        *kbcTypes.Query
	CPE       []ccTypes.Query
}

func (c Criterion) Contains(query Query, repositories []string) (bool, error) {
	switch c.Type {
	case CriterionTypeVersion:
		if c.Version == nil {
			return false, errors.New("criterion is not set for version criterion")
		}
		if len(query.Version) == 0 {
			return false, nil
		}

		for _, q := range query.Version {
			isAccepted, err := c.Version.Accept(q, repositories)
			if err != nil {
				return false, errors.Wrap(err, "version criterion accept")
			}
			if isAccepted {
				return true, nil
			}
		}
		return false, nil
	case CriterionTypeNoneExist:
		if c.NoneExist == nil {
			return false, errors.New("criterion is not set for none exist criterion")
		}
		if query.NoneExist == nil {
			return false, nil
		}

		isAccepted, err := c.NoneExist.Accept(*query.NoneExist, repositories)
		if err != nil {
			return false, errors.Wrap(err, "none exist criterion accept")
		}
		return isAccepted, nil
	case CriterionTypeKB:
		if c.KB == nil {
			return false, errors.New("criterion is not set for kb criterion")
		}
		if query.KB == nil {
			return false, nil
		}

		byCovered, byUnapplied, err := c.KB.Accept(*query.KB)
		if err != nil {
			return false, errors.Wrap(err, "kb criterion accept")
		}
		return byCovered || byUnapplied, nil
	case CriterionTypeCPE:
		if c.CPE == nil {
			return false, errors.New("criterion is not set for cpe criterion")
		}
		if len(query.CPE) == 0 {
			return false, nil
		}

		for _, q := range query.CPE {
			quality, err := c.CPE.Accept(q)
			if err != nil {
				return false, errors.Wrap(err, "cpe criterion accept")
			}
			switch quality {
			case ccTypes.MatchQualityNone:
				// not matched by this query; try the next
			case ccTypes.MatchQualityExact, ccTypes.MatchQualityVersionUnconfirmed:
				return true, nil
			default:
				return false, errors.Errorf("unexpected cpe match quality. expected: %q, actual: %q", []ccTypes.MatchQuality{ccTypes.MatchQualityNone, ccTypes.MatchQualityExact, ccTypes.MatchQualityVersionUnconfirmed}, quality)
			}
		}
		return false, nil
	default:
		// A CriterionType this build cannot evaluate — Unknown, unset, or a
		// value from a newer vuls-data-update — reports "does not contain" so
		// detection skips the criterion instead of aborting.
		return false, nil
	}
}

type FilteredCriterion struct {
	Criterion Criterion     `json:"criterion,omitzero"`
	Accepts   AcceptQueries `json:"accepts,omitzero"`
}

// KB records which evaluation path accepted the KB criterion (i.e., detected
// the vulnerability). Covered=true means the KB was accepted via covered-based
// evaluation (the KB was NOT in the covered set, so it is vulnerable).
// Unapplied=true means the KB was accepted via unapplied-based evaluation.
type KB struct {
	Covered   bool `json:"covered,omitempty"`
	Unapplied bool `json:"unapplied,omitempty"`
}

// CPEAccepts records the indices of accepted CPE queries grouped by match
// quality (see cpecriterion.MatchQuality). Exact holds version-confirmed
// matches; VersionUnconfirmed holds matches accepted on attribute equality but
// without version confirmation. Projecting these onto a consumer's confidence
// model (e.g. vuls0's exact / vendor:product tiers) is the consumer's concern.
type CPEAccepts struct {
	Exact              []int `json:"exact,omitempty"`
	VersionUnconfirmed []int `json:"version_unconfirmed,omitempty"`
}

func (a CPEAccepts) IsZero() bool {
	return len(a.Exact) == 0 && len(a.VersionUnconfirmed) == 0
}

type AcceptQueries struct {
	Version   []int      `json:"version,omitempty"`
	NoneExist bool       `json:"none_exist,omitempty"`
	KB        KB         `json:"kb,omitzero"`
	CPE       CPEAccepts `json:"cpe,omitzero"`
}

func (c Criterion) Accept(query Query, repositories []string) (FilteredCriterion, error) {
	switch c.Type {
	case CriterionTypeVersion:
		if c.Version == nil {
			return FilteredCriterion{}, errors.New("criterion is not set for version criterion")
		}
		if len(query.Version) == 0 {
			return FilteredCriterion{Criterion: c, Accepts: AcceptQueries{}}, nil
		}

		var is []int
		for i, q := range query.Version {
			isAccepted, err := c.Version.Accept(q, repositories)
			if err != nil {
				return FilteredCriterion{}, errors.Wrap(err, "version criterion accept")
			}
			if isAccepted {
				is = append(is, i)
			}
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{Version: is},
		}, nil
	case CriterionTypeNoneExist:
		if c.NoneExist == nil {
			return FilteredCriterion{}, errors.New("criterion is not set for none exist criterion")
		}
		if query.NoneExist == nil {
			return FilteredCriterion{Criterion: c, Accepts: AcceptQueries{}}, nil
		}

		isAccepted, err := c.NoneExist.Accept(*query.NoneExist, repositories)
		if err != nil {
			return FilteredCriterion{}, errors.Wrap(err, "none exist criterion accept")
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{NoneExist: isAccepted},
		}, nil
	case CriterionTypeKB:
		if c.KB == nil {
			return FilteredCriterion{}, errors.New("criterion is not set for kb criterion")
		}
		if query.KB == nil {
			return FilteredCriterion{Criterion: c, Accepts: AcceptQueries{}}, nil
		}

		byCovered, byUnapplied, err := c.KB.Accept(*query.KB)
		if err != nil {
			return FilteredCriterion{}, errors.Wrap(err, "kb criterion accept")
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{KB: KB{Covered: byCovered, Unapplied: byUnapplied}},
		}, nil
	case CriterionTypeCPE:
		if c.CPE == nil {
			return FilteredCriterion{}, errors.New("criterion is not set for cpe criterion")
		}
		if len(query.CPE) == 0 {
			return FilteredCriterion{Criterion: c, Accepts: AcceptQueries{}}, nil
		}

		var accepts CPEAccepts
		for i, q := range query.CPE {
			quality, err := c.CPE.Accept(q)
			if err != nil {
				return FilteredCriterion{}, errors.Wrap(err, "cpe criterion accept")
			}
			switch quality {
			case ccTypes.MatchQualityNone:
				// evaluated, no match; contributes no index
			case ccTypes.MatchQualityExact:
				accepts.Exact = append(accepts.Exact, i)
			case ccTypes.MatchQualityVersionUnconfirmed:
				accepts.VersionUnconfirmed = append(accepts.VersionUnconfirmed, i)
			default:
				return FilteredCriterion{}, errors.Errorf("unexpected cpe match quality. expected: %q, actual: %q", []ccTypes.MatchQuality{ccTypes.MatchQualityNone, ccTypes.MatchQualityExact, ccTypes.MatchQualityVersionUnconfirmed}, quality)
			}
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{CPE: accepts},
		}, nil
	default:
		// A CriterionType this build cannot evaluate — Unknown, unset, or a
		// value from a newer vuls-data-update — accepts no queries;
		// FilteredCriterion.Affected then reports not affected, so detection
		// skips the criterion instead of aborting.
		return FilteredCriterion{Criterion: c, Accepts: AcceptQueries{}}, nil
	}
}

func (fc FilteredCriterion) Affected() (bool, error) {
	switch fc.Criterion.Type {
	case CriterionTypeVersion:
		return len(fc.Accepts.Version) > 0, nil
	case CriterionTypeNoneExist:
		return fc.Accepts.NoneExist, nil
	case CriterionTypeKB:
		return fc.Accepts.KB.Covered || fc.Accepts.KB.Unapplied, nil
	case CriterionTypeCPE:
		return len(fc.Accepts.CPE.Exact) > 0 || len(fc.Accepts.CPE.VersionUnconfirmed) > 0, nil
	default:
		// A CriterionType this build cannot evaluate — Unknown, unset, or a
		// value from a newer vuls-data-update — reports not affected so
		// detection skips the criterion instead of aborting.
		return false, nil
	}
}
