package cpecriterionrange

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	stderrors "errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

// RangeType selects the version comparator used by Compare / Accept. Extractors
// must set it explicitly — Accept on a zero (unset) or Unknown Type refuses to
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
	RangeTypeFortinet
	RangeTypePANOS

	RangeTypeUnknown
)

func (t RangeType) String() string {
	switch t {
	case RangeTypeVersion:
		return "version"
	case RangeTypeSEMVER:
		return "semver"
	case RangeTypeFortinet:
		return "fortinet"
	case RangeTypePANOS:
		return "pan-os"
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
	case "fortinet":
		*t = RangeTypeFortinet
	case "pan-os":
		*t = RangeTypePANOS
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
	case "fortinet":
		rt = RangeTypeFortinet
	case "pan-os":
		rt = RangeTypePANOS
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

// CompareError wraps the failure modes RangeType.Compare can raise so that
// callers can classify them. Mirrors versioncriterion/affected/range's
// pattern: any expected, swallow-safe failure (e.g. an unparseable version)
// is wrapped in CompareError; anything else (e.g. comparator-internal bugs)
// surfaces unwrapped so it propagates loudly.
type CompareError struct {
	Err error
}

func (e *CompareError) Error() string {
	return fmt.Sprintf("compare error. err: %v", e.Err)
}

func (e *CompareError) Unwrap() error { return e.Err }

// NewVersionError records which side (v1 or v2) and which RangeType
// triggered the parse failure.
type NewVersionError struct {
	RangeType RangeType
	Version   string
	Err       error
}

func (e *NewVersionError) Error() string {
	return fmt.Sprintf("new version type %q, string %q: %v", e.RangeType, e.Version, e.Err)
}

func (e *NewVersionError) Unwrap() error { return e.Err }

// ErrRangeTypeUnknown is wrapped in a CompareError when Compare is called
// with a Type that cannot evaluate any version.
var ErrRangeTypeUnknown = errors.New("unknown range type")

// Compare returns an integer comparing v1 and v2 under the comparator
// selected by t (semantics match hashicorp version.Version.Compare):
// negative for v1 < v2, zero for equal, positive for v1 > v2.
//
// Parse failures (either side) are wrapped in *CompareError so that
// detect-time callers can swallow them gracefully. A RangeType with no
// comparator (Unknown or zero) likewise returns a *CompareError wrapping
// ErrRangeTypeUnknown. Any other error (e.g. an unsupported RangeType
// added without a Compare branch, or a comparator-internal failure)
// surfaces unwrapped and propagates loudly.
func (t RangeType) Compare(v1, v2 string) (int, error) {
	switch t {
	case RangeTypeSEMVER:
		va, err := version.NewSemver(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := version.NewSemver(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeFortinet:
		// Why this is not plain semver: Fortinet uses two version schemes. Almost
		// everything is numeric (7.4.3) — and every *range bound* is — but
		// FortiSASE labels releases with a calendar scheme that carries an
		// alphabetic component (25.2.a, 25.1.a.2). semver cannot parse the latter,
		// and a scanned (queried) version can be one, so a Fortinet-specific
		// comparator is needed.
		//
		// compareFortinetVersions walks components: numeric vs numeric
		// numerically, letters lexically (the documented milestone order
		// a < b < c), and a bare train before its builds (25.2 < 25.2.a, while
		// 7.2 == 7.2.0). A numeric component against an alphabetic one at the same
		// position — a build "1.2.1" vs a milestone "1.2.a" — has no defined order
		// across the two schemes, so it is reported INCOMPARABLE rather than
		// guessed: the result is a *CompareError, which Range.Accept swallows as a
		// safe non-match (never a false positive).
		//
		// Why this is safe for detection (under the current data): the incomparable
		// case requires a numeric component to meet an alphabetic one at the same
		// position, i.e. a non-numeric query lined up against a numeric bound that
		// still has a component where the query's letter sits. The Fortinet
		// extractors prevent exactly that at extract time — a range bound is always
		// numeric, and a product with non-numeric versions keeps its ranges train-
		// granular (bound dot <= 1, see csaf.toCriterion / product.IsNonNumericVersioned).
		// So a non-numeric tail only ever meets an *exhausted* bound (25.2 vs 25.2.a),
		// which is comparable, never a numeric component. The incomparable branch is
		// therefore unreachable for today's corpus; if future data (or a bug)
		// reaches it anyway, it fails safe rather than inventing an order.
		c, ok := compareFortinetVersions(v1, v2)
		if !ok {
			return 0, &CompareError{Err: errors.Errorf("incomparable fortinet versions %q and %q", v1, v2)}
		}
		return c, nil
	case RangeTypeVersion:
		va, err := version.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := version.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypePANOS:
		// PAN-OS versions are <major>.<minor>.<maintenance>[-h<hotfix>].
		// hashicorp comparators must not be used here: they parse "-hN" as a
		// prerelease and invert the order (11.2.4-h1 < 11.2.4), while in
		// PAN-OS a hotfix is released after its base (11.2.4 < 11.2.4-h1).
		va, err := panosVersion.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := panosVersion.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeUnknown, 0:
		// Unknown (explicit) and the zero value (unset) collapse to the same
		// graceful "cannot evaluate" outcome — callers swallow this via
		// CompareError. Forgetting to set Type therefore produces a safe
		// non-match rather than a loud error.
		return 0, &CompareError{Err: ErrRangeTypeUnknown}
	default:
		return 0, errors.Errorf("unsupported range type: %s", t)
	}
}

// compareFortinetVersions compares two Fortinet version strings component by
// component (split on ".") and reports whether they are comparable at all.
// Numeric components compare numerically and alphabetic ones lexically (the
// FortiSASE calendar letters a < b < c). When one version runs out of components
// the other's tail decides, with trailing zeros treated as equal (7.2 == 7.2.0)
// but any non-zero or lettered tail making the longer version greater — so a
// bare train precedes its builds (25.2 < 25.2.a). The two are NOT comparable
// when, at the same position, one component is numeric and the other alphabetic
// (e.g. a build "1.2.1" against a milestone "1.2.a"), which is undefined across
// Fortinet's numeric and calendar schemes.
func compareFortinetVersions(a, b string) (order int, comparable bool) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	// An empty component (consecutive/leading/trailing dot, e.g. "7..0" or
	// "7.2.") is malformed; refuse to order it so Range.Accept fails safe
	// (non-match) on malformed scan input rather than inventing an order.
	if slices.Contains(as, "") || slices.Contains(bs, "") {
		return 0, false
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		switch {
		case i >= len(as):
			return -tailSign(bs[i:]), true
		case i >= len(bs):
			return tailSign(as[i:]), true
		}
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return cmp.Compare(an, bn), true
			}
		case aerr != nil && berr != nil:
			if as[i] != bs[i] {
				return strings.Compare(as[i], bs[i]), true
			}
		default:
			return 0, false // numeric vs alphabetic at the same position
		}
	}
	return 0, true
}

// tailSign reports whether the trailing components of a longer version make it
// greater than a shorter one sharing its prefix: 0 when every component is a
// numeric zero (a trailing-zero no-op, 7.2 == 7.2.0), 1 otherwise (a non-zero or
// lettered tail, 25.2 < 25.2.a).
func tailSign(comps []string) int {
	for _, c := range comps {
		if n, err := strconv.Atoi(c); err != nil || n != 0 {
			return 1
		}
	}
	return 0
}

// Accept returns true when v satisfies every non-empty bound on r, comparing
// via r.Type.Compare. An empty Range (all four bound strings unset) with a
// usable Type accepts any v — even an unparseable one — because "no bound"
// means "no constraint"; an empty Range with Type=Unknown/unset still
// returns false (no constraint can be evaluated).
//
// Compare failures that classify as *CompareError (parse failures on either
// bound or query, plus Unknown-type sentinel) are swallowed as graceful
// non-matches so a detect run against malformed scan input does not crash.
// Other errors (e.g. an unsupported RangeType that landed in data without a
// matching Compare branch) propagate so the caller can surface the
// data-invariant violation. Mirrors versioncriterion/affected.Accept.
func (r Range) Accept(v string) (bool, error) {
	if r.GreaterEqual == "" && r.GreaterThan == "" && r.LessEqual == "" && r.LessThan == "" {
		// No bounds → no narrowing, but Unknown / unset Type still
		// refuses to declare a match.
		if r.Type == RangeTypeUnknown || r.Type == 0 {
			return false, nil
		}
		return true, nil
	}

	type bound struct {
		label string
		s     string
		// reject reports whether the Compare(bound, v) sign should
		// disqualify the criterion (i.e. the bound is violated).
		reject func(int) bool
	}
	bounds := []bound{
		{"ge", r.GreaterEqual, func(n int) bool { return n > 0 }}, // need bound <= v
		{"gt", r.GreaterThan, func(n int) bool { return n >= 0 }}, // need bound <  v
		{"le", r.LessEqual, func(n int) bool { return n < 0 }},    // need bound >= v
		{"lt", r.LessThan, func(n int) bool { return n <= 0 }},    // need bound >  v
	}
	for _, b := range bounds {
		if b.s == "" {
			continue
		}
		n, err := r.Type.Compare(b.s, v)
		if err != nil {
			if _, ok := stderrors.AsType[*CompareError](err); ok {
				return false, nil
			}
			return false, errors.Wrapf(err, "compare bound %s %q against %q (type %s)", b.label, b.s, v, r.Type)
		}
		if b.reject(n) {
			return false, nil
		}
	}
	return true, nil
}
