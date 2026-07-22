package criterion

import (
	"cmp"
	stderrors "errors"
	"slices"

	"github.com/pkg/errors"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
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
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// CriterionTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t CriterionType) Compare(u CriterionType) int {
	return vocabulary.Compare(t, u)
}

// Known reports whether t is in this build's vocabulary. Data from a newer
// vuls-data-update may carry values for which Known is false.
func (t CriterionType) Known() bool {
	return vocabulary.Contains(t)
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

type FilteredCriterion struct {
	Criterion Criterion     `json:"criterion,omitzero"`
	Accepts   AcceptQueries `json:"accepts,omitzero"`
	// Warnings records non-fatal evaluation events — e.g. enum values this
	// build could not evaluate (data from a newer vuls-data-update). The
	// detection types never log; callers project these into logs or
	// scan-result warnings by walking the FilteredCriteria tree.
	Warnings []warningTypes.Warning `json:"warnings,omitempty"`
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
		var ws []warningTypes.Warning
		for i, q := range query.Version {
			isAccepted, err := c.Version.Accept(q, repositories)
			if err != nil {
				// The layer that could not evaluate its own data reports it
				// as a non-fatal *warning.UnevaluableError; record it once
				// and treat the query as not accepted.
				if ue, ok := stderrors.AsType[*warningTypes.UnevaluableError](err); ok {
					if !slices.Contains(ws, ue.Warning) {
						ws = append(ws, ue.Warning)
					}
					continue
				}
				return FilteredCriterion{}, errors.Wrap(err, "version criterion accept")
			}
			if isAccepted {
				is = append(is, i)
			}
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{Version: is},
			Warnings:  ws,
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
			if ue, ok := stderrors.AsType[*warningTypes.UnevaluableError](err); ok {
				return FilteredCriterion{Criterion: c, Warnings: []warningTypes.Warning{ue.Warning}}, nil
			}
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
		var ws []warningTypes.Warning
		for i, q := range query.CPE {
			quality, err := c.CPE.Accept(q)
			if err != nil {
				if ue, ok := stderrors.AsType[*warningTypes.UnevaluableError](err); ok {
					if !slices.Contains(ws, ue.Warning) {
						ws = append(ws, ue.Warning)
					}
					continue
				}
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
			Warnings:  ws,
		}, nil
	default:
		// A criterion type outside this build's vocabulary (data from a
		// newer vuls-data-update) contributes "not affected", recorded on
		// the result so callers can surface it.
		if !c.Type.Known() {
			return FilteredCriterion{Criterion: c, Warnings: []warningTypes.Warning{{Kind: warningTypes.KindUnevaluableCriterionType, Cause: string(c.Type)}}}, nil
		}
		// In the vocabulary but not dispatched above: the vocabulary and
		// this switch are out of sync within this build — a bug, not newer
		// data. Fail loudly (mirrors the criteria operator default).
		return FilteredCriterion{}, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", CriterionTypes(), c.Type)
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
		// Data from a newer vuls-data-update: not affected; the warning was
		// recorded when Accept produced this FilteredCriterion.
		if !fc.Criterion.Type.Known() {
			return false, nil
		}
		// In the vocabulary but not dispatched above: the vocabulary and
		// this switch are out of sync within this build — a bug, not newer
		// data. Fail loudly (mirrors the criteria operator default).
		return false, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", CriterionTypes(), fc.Criterion.Type)
	}
}
