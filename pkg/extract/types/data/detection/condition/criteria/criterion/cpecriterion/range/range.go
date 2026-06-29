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
// rather than a silent false positive. The `type` JSON tag carries `omitempty`,
// so a zero value is omitted from output; an explicitly-set Unknown serializes
// as "unknown".
//
// Independent from versioncriterion/affected/range.RangeType: only types
// meaningful for CPE-side matching belong here.
type RangeType int

const (
	_ RangeType = iota
	RangeTypeVersion
	RangeTypeSEMVER
	RangeTypePANOS

	// Fortinet uses one RangeType per product. RangeType.Compare receives only
	// the two version strings (no product context), so a product whose
	// versioning scheme later diverges must carry its own type to get its own
	// comparator without changing how any other product is compared — and adding
	// a type stays additive (existing products are untouched). Today every
	// product is purely numeric except the FortiSASE calendar scheme (see
	// fortinetCalendarTypes); the per-product split is what lets that stay true
	// product-by-product going forward.
	RangeTypeFortinetAntivirusEngine
	RangeTypeFortinetAscenlink
	RangeTypeFortinetFortiadc
	RangeTypeFortinetFortiadcManager
	RangeTypeFortinetFortiaiops
	RangeTypeFortinetFortianalyzer
	RangeTypeFortinetFortianalyzerBigdata
	RangeTypeFortinetFortianalyzerCloud
	RangeTypeFortinetFortiap
	RangeTypeFortinetFortiapC
	RangeTypeFortinetFortiapS
	RangeTypeFortinetFortiapU
	RangeTypeFortinetFortiapW2
	RangeTypeFortinetFortiauthenticator
	RangeTypeFortinetForticache
	RangeTypeFortinetForticamera
	RangeTypeFortinetForticlient
	RangeTypeFortinetForticlientEnterpriseManagementServer
	RangeTypeFortinetForticlientEnterpriseManagementServerCloud
	RangeTypeFortinetForticonverter
	RangeTypeFortinetFortidb
	RangeTypeFortinetFortiddos
	RangeTypeFortinetFortiddosCm
	RangeTypeFortinetFortiddosF
	RangeTypeFortinetFortideceptor
	RangeTypeFortinetFortidlp
	RangeTypeFortinetFortiedr
	RangeTypeFortinetFortiedrManager
	RangeTypeFortinetFortiextender
	RangeTypeFortinetFortifone
	RangeTypeFortinetFortiguest
	RangeTypeFortinetFortiisolator
	RangeTypeFortinetFortimail
	RangeTypeFortinetFortimanager
	RangeTypeFortinetFortimanagerCloud
	RangeTypeFortinetFortinac
	RangeTypeFortinetFortinacF
	RangeTypeFortinetFortindr
	RangeTypeFortinetFortios
	RangeTypeFortinetFortios6k7k
	RangeTypeFortinetFortiosIpsEngine
	RangeTypeFortinetFortipam
	RangeTypeFortinetFortiportal
	RangeTypeFortinetFortipresence
	RangeTypeFortinetFortiproxy
	RangeTypeFortinetFortirecorder
	RangeTypeFortinetFortisandbox
	RangeTypeFortinetFortisandboxCloud
	RangeTypeFortinetFortisandboxPaas
	RangeTypeFortinetFortisase
	RangeTypeFortinetFortisiem
	RangeTypeFortinetFortisoar
	RangeTypeFortinetFortisoarAgentCommunicationBridge
	RangeTypeFortinetFortisra
	RangeTypeFortinetFortiswitch
	RangeTypeFortinetFortiswitchaxfixed
	RangeTypeFortinetFortiswitchmanager
	RangeTypeFortinetFortitester
	RangeTypeFortinetFortitokenMobile
	RangeTypeFortinetFortivoice
	RangeTypeFortinetFortivoiceCloudUnifiedCommunicationsDesktop
	RangeTypeFortinetFortiwan
	RangeTypeFortinetFortiwanManager
	RangeTypeFortinetFortiweb
	RangeTypeFortinetFortiwebManager
	RangeTypeFortinetFortiwlc
	RangeTypeFortinetFortiwlm
	RangeTypeFortinetMeru

	RangeTypeUnknown
)

// rangeTypeNames is the single source of truth mapping each RangeType to its
// serialized string; rangeTypeByName is its inverse.
var rangeTypeNames = map[RangeType]string{
	RangeTypeVersion:                                             "version",
	RangeTypeSEMVER:                                              "semver",
	RangeTypePANOS:                                               "pan-os",
	RangeTypeUnknown:                                             "unknown",
	RangeTypeFortinetAntivirusEngine:                             "fortinet-antivirus_engine",
	RangeTypeFortinetAscenlink:                                   "fortinet-ascenlink",
	RangeTypeFortinetFortiadc:                                    "fortinet-fortiadc",
	RangeTypeFortinetFortiadcManager:                             "fortinet-fortiadc_manager",
	RangeTypeFortinetFortiaiops:                                  "fortinet-fortiaiops",
	RangeTypeFortinetFortianalyzer:                               "fortinet-fortianalyzer",
	RangeTypeFortinetFortianalyzerBigdata:                        "fortinet-fortianalyzer-bigdata",
	RangeTypeFortinetFortianalyzerCloud:                          "fortinet-fortianalyzer_cloud",
	RangeTypeFortinetFortiap:                                     "fortinet-fortiap",
	RangeTypeFortinetFortiapC:                                    "fortinet-fortiap-c",
	RangeTypeFortinetFortiapS:                                    "fortinet-fortiap-s",
	RangeTypeFortinetFortiapU:                                    "fortinet-fortiap-u",
	RangeTypeFortinetFortiapW2:                                   "fortinet-fortiap-w2",
	RangeTypeFortinetFortiauthenticator:                          "fortinet-fortiauthenticator",
	RangeTypeFortinetForticache:                                  "fortinet-forticache",
	RangeTypeFortinetForticamera:                                 "fortinet-forticamera",
	RangeTypeFortinetForticlient:                                 "fortinet-forticlient",
	RangeTypeFortinetForticlientEnterpriseManagementServer:       "fortinet-forticlient_enterprise_management_server",
	RangeTypeFortinetForticlientEnterpriseManagementServerCloud:  "fortinet-forticlient_enterprise_management_server_cloud",
	RangeTypeFortinetForticonverter:                              "fortinet-forticonverter",
	RangeTypeFortinetFortidb:                                     "fortinet-fortidb",
	RangeTypeFortinetFortiddos:                                   "fortinet-fortiddos",
	RangeTypeFortinetFortiddosCm:                                 "fortinet-fortiddos-cm",
	RangeTypeFortinetFortiddosF:                                  "fortinet-fortiddos-f",
	RangeTypeFortinetFortideceptor:                               "fortinet-fortideceptor",
	RangeTypeFortinetFortidlp:                                    "fortinet-fortidlp",
	RangeTypeFortinetFortiedr:                                    "fortinet-fortiedr",
	RangeTypeFortinetFortiedrManager:                             "fortinet-fortiedr_manager",
	RangeTypeFortinetFortiextender:                               "fortinet-fortiextender",
	RangeTypeFortinetFortifone:                                   "fortinet-fortifone",
	RangeTypeFortinetFortiguest:                                  "fortinet-fortiguest",
	RangeTypeFortinetFortiisolator:                               "fortinet-fortiisolator",
	RangeTypeFortinetFortimail:                                   "fortinet-fortimail",
	RangeTypeFortinetFortimanager:                                "fortinet-fortimanager",
	RangeTypeFortinetFortimanagerCloud:                           "fortinet-fortimanager_cloud",
	RangeTypeFortinetFortinac:                                    "fortinet-fortinac",
	RangeTypeFortinetFortinacF:                                   "fortinet-fortinac-f",
	RangeTypeFortinetFortindr:                                    "fortinet-fortindr",
	RangeTypeFortinetFortios:                                     "fortinet-fortios",
	RangeTypeFortinetFortios6k7k:                                 "fortinet-fortios-6k7k",
	RangeTypeFortinetFortiosIpsEngine:                            "fortinet-fortios_ips_engine",
	RangeTypeFortinetFortipam:                                    "fortinet-fortipam",
	RangeTypeFortinetFortiportal:                                 "fortinet-fortiportal",
	RangeTypeFortinetFortipresence:                               "fortinet-fortipresence",
	RangeTypeFortinetFortiproxy:                                  "fortinet-fortiproxy",
	RangeTypeFortinetFortirecorder:                               "fortinet-fortirecorder",
	RangeTypeFortinetFortisandbox:                                "fortinet-fortisandbox",
	RangeTypeFortinetFortisandboxCloud:                           "fortinet-fortisandbox_cloud",
	RangeTypeFortinetFortisandboxPaas:                            "fortinet-fortisandbox_paas",
	RangeTypeFortinetFortisase:                                   "fortinet-fortisase",
	RangeTypeFortinetFortisiem:                                   "fortinet-fortisiem",
	RangeTypeFortinetFortisoar:                                   "fortinet-fortisoar",
	RangeTypeFortinetFortisoarAgentCommunicationBridge:           "fortinet-fortisoar_agent_communication_bridge",
	RangeTypeFortinetFortisra:                                    "fortinet-fortisra",
	RangeTypeFortinetFortiswitch:                                 "fortinet-fortiswitch",
	RangeTypeFortinetFortiswitchaxfixed:                          "fortinet-fortiswitchaxfixed",
	RangeTypeFortinetFortiswitchmanager:                          "fortinet-fortiswitchmanager",
	RangeTypeFortinetFortitester:                                 "fortinet-fortitester",
	RangeTypeFortinetFortitokenMobile:                            "fortinet-fortitoken_mobile",
	RangeTypeFortinetFortivoice:                                  "fortinet-fortivoice",
	RangeTypeFortinetFortivoiceCloudUnifiedCommunicationsDesktop: "fortinet-fortivoice_cloud_unified_communications_desktop",
	RangeTypeFortinetFortiwan:                                    "fortinet-fortiwan",
	RangeTypeFortinetFortiwanManager:                             "fortinet-fortiwan_manager",
	RangeTypeFortinetFortiweb:                                    "fortinet-fortiweb",
	RangeTypeFortinetFortiwebManager:                             "fortinet-fortiweb_manager",
	RangeTypeFortinetFortiwlc:                                    "fortinet-fortiwlc",
	RangeTypeFortinetFortiwlm:                                    "fortinet-fortiwlm",
	RangeTypeFortinetMeru:                                        "fortinet-meru",
}

var rangeTypeByName = func() map[string]RangeType {
	m := make(map[string]RangeType, len(rangeTypeNames))
	for t, s := range rangeTypeNames {
		m[s] = t
	}
	return m
}()

// fortinetCalendarTypes are the Fortinet per-product types whose versions use
// the FortiSASE-style calendar scheme (an alphabetic milestone component, e.g.
// 25.2.a); every other Fortinet type is purely numeric.
var fortinetCalendarTypes = map[RangeType]struct{}{
	RangeTypeFortinetFortisase: {},
}

// IsFortinetCalendar reports whether t is a Fortinet per-product type that uses
// the calendar version scheme.
func IsFortinetCalendar(t RangeType) bool {
	_, ok := fortinetCalendarTypes[t]
	return ok
}

// FortinetRangeTypeBySlug returns the per-product RangeType for a Fortinet CPE
// product slug (e.g. "fortios" -> RangeTypeFortinetFortios). ok is false when
// the slug has no type, so the caller can hard-error and a new product gets
// noticed rather than silently mis-compared.
func FortinetRangeTypeBySlug(slug string) (RangeType, bool) {
	t, ok := rangeTypeByName["fortinet-"+slug]
	return t, ok
}

func (t RangeType) String() string {
	if s, ok := rangeTypeNames[t]; ok {
		return s
	}
	return "unknown"
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
	rt, ok := rangeTypeByName[token.String()]
	if !ok {
		return fmt.Errorf("invalid RangeType %s", token.String())
	}
	*t = rt
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
	rt, ok := rangeTypeByName[s]
	if !ok {
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
// callers can classify them: any expected, swallow-safe failure (e.g. an
// unparseable version) is wrapped in CompareError; anything else surfaces
// unwrapped so it propagates loudly.
type CompareError struct {
	Err error
}

func (e *CompareError) Error() string {
	return fmt.Sprintf("compare error. err: %v", e.Err)
}

func (e *CompareError) Unwrap() error { return e.Err }

// NewVersionError records which side (v1 or v2) and which RangeType triggered
// the parse failure.
type NewVersionError struct {
	RangeType RangeType
	Version   string
	Err       error
}

func (e *NewVersionError) Error() string {
	return fmt.Sprintf("new version type %q, string %q: %v", e.RangeType, e.Version, e.Err)
}

func (e *NewVersionError) Unwrap() error { return e.Err }

// ErrRangeTypeUnknown is wrapped in a CompareError when Compare is called with a
// Type that cannot evaluate any version.
var ErrRangeTypeUnknown = errors.New("unknown range type")

// Compare returns an integer comparing v1 and v2 under the comparator selected
// by t: negative for v1 < v2, zero for equal, positive for v1 > v2.
//
// Parse failures (either side) are wrapped in *CompareError so detect-time
// callers can swallow them gracefully; a Type with no comparator (Unknown/zero)
// likewise returns a *CompareError wrapping ErrRangeTypeUnknown. Any other error
// surfaces unwrapped and propagates loudly.
//
// Fortinet per-product types dispatch to one of two comparators: the FortiSASE
// calendar scheme (fortinetCalendarTypes) vs. the numeric scheme everything else
// uses. The numeric comparator refuses to order a non-numeric component, so a
// numeric product never matches a calendar/letter version (it fails safe via
// CompareError); a product that later adopts a different scheme moves to its own
// branch without touching the others.
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
		// prerelease and invert the order (11.2.4-h1 < 11.2.4), while in PAN-OS a
		// hotfix is released after its base (11.2.4 < 11.2.4-h1).
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
		name, known := rangeTypeNames[t]
		if !known || !strings.HasPrefix(name, "fortinet-") {
			return 0, errors.Errorf("unsupported range type: %s", t)
		}
		var (
			c  int
			ok bool
		)
		if IsFortinetCalendar(t) {
			c, ok = compareFortinetCalendar(v1, v2)
		} else {
			c, ok = compareFortinetNumeric(v1, v2)
		}
		if !ok {
			return 0, &CompareError{Err: errors.Errorf("incomparable fortinet versions %q and %q (type %s)", v1, v2, t)}
		}
		return c, nil
	}
}

// compareFortinetNumeric compares two purely numeric Fortinet version strings
// (dot-separated, e.g. 7.4.3 or train 7.2). Any non-numeric component — a
// milestone letter, or an empty component from a stray dot — makes the pair
// incomparable, so a numeric product never orders a calendar/letter version and
// Range.Accept fails safe (non-match). Trailing zeros are a no-op (7.2 == 7.2.0).
func compareFortinetNumeric(a, b string) (order int, comparable bool) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for _, c := range as {
		if _, err := strconv.Atoi(c); err != nil {
			return 0, false
		}
	}
	for _, c := range bs {
		if _, err := strconv.Atoi(c); err != nil {
			return 0, false
		}
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		switch {
		case i >= len(as):
			return -tailSign(bs[i:]), true
		case i >= len(bs):
			return tailSign(as[i:]), true
		}
		an, _ := strconv.Atoi(as[i])
		bn, _ := strconv.Atoi(bs[i])
		if an != bn {
			return cmp.Compare(an, bn), true
		}
	}
	return 0, true
}

// compareFortinetCalendar compares two FortiSASE-style calendar version strings
// component by component (split on ".") and reports whether they are comparable
// at all. Numeric components compare numerically and alphabetic ones lexically
// (the milestone letters a < b < c). When one version runs out of components the
// other's tail decides, with trailing zeros treated as equal (7.2 == 7.2.0) but
// any non-zero or lettered tail making the longer version greater — so a bare
// train precedes its builds (25.2 < 25.2.a). The two are NOT comparable when, at
// the same position, one component is numeric and the other alphabetic (e.g. a
// build "1.2.1" against a milestone "1.2.a"), or when a component is empty (a
// stray dot), so Range.Accept fails safe on malformed input.
func compareFortinetCalendar(a, b string) (order int, comparable bool) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
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

// Accept returns true when v satisfies every non-empty bound on r, comparing via
// r.Type.Compare. An empty Range (all four bound strings unset) with a usable
// Type accepts any v — even an unparseable one — because "no bound" means "no
// constraint"; an empty Range with Type=Unknown/unset still returns false.
//
// Compare failures that classify as *CompareError (parse failures on either
// bound or query, plus the Unknown-type sentinel) are swallowed as graceful
// non-matches so a detect run against malformed scan input does not crash. Other
// errors propagate. Mirrors versioncriterion/affected.Accept.
func (r Range) Accept(v string) (bool, error) {
	if r.GreaterEqual == "" && r.GreaterThan == "" && r.LessEqual == "" && r.LessThan == "" {
		if r.Type == RangeTypeUnknown || r.Type == 0 {
			return false, nil
		}
		return true, nil
	}

	type bound struct {
		label  string
		s      string
		reject func(int) bool
	}
	bounds := []bound{
		{"ge", r.GreaterEqual, func(n int) bool { return n > 0 }},
		{"gt", r.GreaterThan, func(n int) bool { return n >= 0 }},
		{"le", r.LessEqual, func(n int) bool { return n < 0 }},
		{"lt", r.LessThan, func(n int) bool { return n <= 0 }},
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
