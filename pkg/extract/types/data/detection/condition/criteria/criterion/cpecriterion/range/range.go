package cpecriterionrange

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/hashicorp/go-version"
)

// RangeType selects the version comparator used by Accept. Extractors must
// set it explicitly — Accept on a zero (unset) or Unknown Type refuses to
// evaluate (returns false), so a forgotten Type produces a safe non-match
// rather than a silent false positive. The `type` JSON tag carries
// `omitempty`, so a zero value is omitted from output rather than written
// as "unknown"; an explicitly-set Unknown is serialized as "unknown".
//
// Independent from versioncriterion/affected/range.RangeType: only types
// meaningful for CPE-side matching belong here. Add new comparators (e.g.
// cisco IOS train versions) as needed.
type RangeType int

const (
	_ RangeType = iota
	RangeTypeVersion
	RangeTypeSEMVER

	RangeTypeUnknown
)

func (t RangeType) String() string {
	switch t {
	case RangeTypeVersion:
		return "version"
	case RangeTypeSEMVER:
		return "semver"
	default:
		return "unknown"
	}
}

func (t RangeType) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(t.String()))
}

func (t *RangeType) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '"' {
		return fmt.Errorf("unexpected type. expected: %s, got %s", "string", token.Kind())
	}

	switch token.String() {
	case "version":
		*t = RangeTypeVersion
	case "semver":
		*t = RangeTypeSEMVER
	case "unknown":
		*t = RangeTypeUnknown
	default:
		return fmt.Errorf("invalid RangeType %s", token.String())
	}
	return nil
}

func (t RangeType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *RangeType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var rt RangeType
	switch s {
	case "version":
		rt = RangeTypeVersion
	case "semver":
		rt = RangeTypeSEMVER
	case "unknown":
		rt = RangeTypeUnknown
	default:
		return fmt.Errorf("invalid RangeType %s", s)
	}
	*t = rt
	return nil
}

// Range is a version constraint for a CPE criterion. Type selects the
// comparator; bounds are inclusive (Greater/LessEqual) or exclusive
// (Greater/LessThan). Unlike versioncriterion/affected/Range there is no
// Fixed[] and the criterion holds a single Range (not a slice).
type Range struct {
	Type         RangeType `json:"type,omitempty"`
	GreaterEqual string    `json:"ge,omitempty"`
	GreaterThan  string    `json:"gt,omitempty"`
	LessEqual    string    `json:"le,omitempty"`
	LessThan     string    `json:"lt,omitempty"`
}

func Compare(x, y Range) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.GreaterEqual, y.GreaterEqual),
		cmp.Compare(x.GreaterThan, y.GreaterThan),
		cmp.Compare(x.LessEqual, y.LessEqual),
		cmp.Compare(x.LessThan, y.LessThan),
	)
}

// Accept returns true when v satisfies every non-empty bound on r, parsing
// both r's bounds and v with the comparator selected by r.Type. An
// unparseable version (bound or query) is treated as "out of range" without
// an error so callers can still try alternative detection paths (e.g.
// CPEMatches enumeration).
//
// Unknown (or unset) Type returns (false, nil) — the data lacked enough
// information to evaluate.
func (r Range) Accept(v string) (bool, error) {
	switch r.Type {
	case RangeTypeSEMVER:
		return r.acceptWith(v, func(s string) (*version.Version, error) { return version.NewSemver(s) })
	case RangeTypeVersion:
		return r.acceptWith(v, func(s string) (*version.Version, error) { return version.NewVersion(s) })
	default:
		return false, nil
	}
}

func (r Range) acceptWith(v string, parse func(string) (*version.Version, error)) (bool, error) {
	// No bounds → no narrowing. Short-circuit before parsing v so an empty
	// Range with an unparseable query still returns true (treat empty
	// constraints as "accept anything").
	if r.GreaterEqual == "" && r.GreaterThan == "" && r.LessEqual == "" && r.LessThan == "" {
		return true, nil
	}

	qv, err := parse(v)
	if err != nil {
		return false, nil
	}

	if r.GreaterEqual != "" {
		bv, err := parse(r.GreaterEqual)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) < 0 {
			return false, nil
		}
	}
	if r.GreaterThan != "" {
		bv, err := parse(r.GreaterThan)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) <= 0 {
			return false, nil
		}
	}
	if r.LessEqual != "" {
		bv, err := parse(r.LessEqual)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) > 0 {
			return false, nil
		}
	}
	if r.LessThan != "" {
		bv, err := parse(r.LessThan)
		if err != nil {
			return false, nil
		}
		if qv.Compare(bv) >= 0 {
			return false, nil
		}
	}
	return true, nil
}
