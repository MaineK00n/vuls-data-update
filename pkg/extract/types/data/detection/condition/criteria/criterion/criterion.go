package criterion

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/pkg/errors"

	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
)

type CriterionType int

const (
	_ CriterionType = iota
	CriterionTypeVersion
	CriterionTypeNoneExist
	CriterionTypeKB

	CriterionTypeUnknown
)

func (t CriterionType) String() string {
	switch t {
	case CriterionTypeVersion:
		return "version"
	case CriterionTypeNoneExist:
		return "none-exist"
	case CriterionTypeKB:
		return "kb"
	default:
		return "unknown"
	}
}

func (t CriterionType) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(t.String()))
}

func (t *CriterionType) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '"' {
		return fmt.Errorf("unexpected type. expected: %s, got %s", "string", token.Kind())
	}

	switch token.String() {
	case "version":
		*t = CriterionTypeVersion
	case "none-exist":
		*t = CriterionTypeNoneExist
	case "kb":
		*t = CriterionTypeKB
	case "unknown":
		*t = CriterionTypeUnknown
	default:
		return fmt.Errorf("invalid CriterionType %s", token.String())
	}
	return nil
}

func (t CriterionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *CriterionType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var ct CriterionType
	switch s {
	case "version":
		ct = CriterionTypeVersion
	case "none-exist":
		ct = CriterionTypeNoneExist
	case "kb":
		ct = CriterionTypeKB
	case "unknown":
		ct = CriterionTypeUnknown
	default:
		return fmt.Errorf("invalid CriterionType %s", s)
	}
	*t = ct
	return nil
}

type Criterion struct {
	Type      CriterionType       `json:"type,omitempty"`
	Version   *vcTypes.Criterion  `json:"version,omitempty"`
	NoneExist *necTypes.Criterion `json:"none_exist,omitempty"`
	KB        *kbcTypes.Criterion `json:"kb,omitempty"`
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
	default:
	}
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
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
}

func (c Criterion) Contains(query Query, repositories []string) (bool, error) {
	switch c.Type {
	case CriterionTypeVersion:
		if c.Version == nil {
			return false, errors.New("criterion is not set for version criterion")
		}
		if len(query.Version) == 0 {
			return false, errors.New("query is not set for version criterion")
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
			return false, errors.New("query is not set for none exist criterion")
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
			return false, errors.New("query is not set for kb criterion")
		}

		isAccepted, err := c.KB.Accept(*query.KB)
		if err != nil {
			return false, errors.Wrap(err, "kb criterion accept")
		}
		return isAccepted, nil
	default:
		return false, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []CriterionType{CriterionTypeVersion, CriterionTypeNoneExist, CriterionTypeKB}, c.Type)
	}
}

type FilteredCriterion struct {
	Criterion Criterion     `json:"criterion,omitzero"`
	Accepts   AcceptQueries `json:"accepts,omitzero"`
}

type AcceptQueries struct {
	Version   []int `json:"version,omitempty"`
	NoneExist bool  `json:"none_exist,omitempty"`
	KB        bool  `json:"kb,omitempty"`
}

func (c Criterion) Accept(query Query, repositories []string) (FilteredCriterion, error) {
	switch c.Type {
	case CriterionTypeVersion:
		if c.Version == nil {
			return FilteredCriterion{}, errors.New("criterion is not set for version criterion")
		}
		if len(query.Version) == 0 {
			return FilteredCriterion{}, errors.New("query is not set for version criterion")
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
			return FilteredCriterion{}, errors.New("query is not set for none exist criterion")
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
			return FilteredCriterion{}, errors.New("query is not set for kb criterion")
		}

		isAccepted, err := c.KB.Accept(*query.KB)
		if err != nil {
			return FilteredCriterion{}, errors.Wrap(err, "kb criterion accept")
		}
		return FilteredCriterion{
			Criterion: c,
			Accepts:   AcceptQueries{KB: isAccepted},
		}, nil
	default:
		return FilteredCriterion{}, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []CriterionType{CriterionTypeVersion, CriterionTypeNoneExist, CriterionTypeKB}, c.Type)
	}
}

func (fc FilteredCriterion) Affected() (bool, error) {
	switch fc.Criterion.Type {
	case CriterionTypeVersion:
		return len(fc.Accepts.Version) > 0, nil
	case CriterionTypeNoneExist:
		return fc.Accepts.NoneExist, nil
	case CriterionTypeKB:
		return fc.Accepts.KB, nil
	default:
		return false, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []CriterionType{CriterionTypeVersion, CriterionTypeNoneExist, CriterionTypeKB}, fc.Criterion.Type)
	}
}
