package cpecriterionrange

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	stderrors "errors"
	"fmt"
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
	// product is purely numeric except the FortiSASE non-numeric scheme (see
	// fortinetNonNumericTypes); the per-product split is what lets that stay true
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

// fortinetNonNumericTypes are the Fortinet per-product types whose versions use
// the FortiSASE non-numeric scheme (an alphabetic milestone component, e.g.
// 25.2.a); every other Fortinet type is purely numeric.
var fortinetNonNumericTypes = map[RangeType]struct{}{
	RangeTypeFortinetFortisase: {},
}

// IsFortinetNonNumeric reports whether t is a Fortinet per-product type that uses
// the non-numeric version scheme (the product → type mapping lives in the
// fortinet product table).
func IsFortinetNonNumeric(t RangeType) bool {
	_, ok := fortinetNonNumericTypes[t]
	return ok
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
// non-numeric scheme (fortinetNonNumericTypes) vs. the numeric scheme everything else
// uses. The numeric comparator refuses to order a non-numeric component, so a
// numeric product never matches a non-numeric (letter) version (it fails safe via
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
		c, ok := compareFortinet(v1, v2, IsFortinetNonNumeric(t))
		if !ok {
			return 0, &CompareError{Err: errors.Errorf("incomparable fortinet versions %q and %q (type %s)", v1, v2, t)}
		}
		return c, nil
	}
}

// fortinetComp classifies one "."-separated version component. A component is
// either unsigned digits (strconv.ParseUint — so signed "+0"/"-1", overflow,
// and empty all fail) or a single lowercase milestone letter (a, b, c, …).
// Anything else is invalid, which makes the version incomparable so malformed
// scan input fails safe (non-match) rather than matching a range.
type fortinetComp struct {
	num     uint64
	letter  byte
	numeric bool
	valid   bool
}

func classifyFortinetComp(s string) fortinetComp {
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		return fortinetComp{num: n, numeric: true, valid: true}
	}
	if len(s) == 1 && s[0] >= 'a' && s[0] <= 'z' {
		return fortinetComp{letter: s[0], valid: true}
	}
	return fortinetComp{}
}

// compareFortinet compares two Fortinet version strings component by component
// (split on "."). Numeric components compare numerically; when allowLetters is
// true a single milestone letter (a < b < c) is also valid and compares
// lexically (FortiSASE), otherwise only numeric components are accepted. A
// component that is invalid (empty, a signed/overflowing number, or — and when
// allowLetters — a multi-char/non-[a-z] token like "alpha"/"a10"), or a
// numeric-vs-letter mismatch at the same position, makes the pair incomparable
// so Range.Accept fails safe (non-match). When one side is a prefix of the
// other the remaining tail decides (see fortinetTailSign): trailing zeros are
// equal (7.2 == 7.2.0), a non-zero or lettered tail makes the longer side
// greater (a bare train precedes its builds, 25.2 < 25.2.a).
func compareFortinet(a, b string, allowLetters bool) (order int, comparable bool) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		switch {
		case i >= len(as):
			return fortinetTailSign(bs[i:], -1, allowLetters)
		case i >= len(bs):
			return fortinetTailSign(as[i:], 1, allowLetters)
		}
		ca, cb := classifyFortinetComp(as[i]), classifyFortinetComp(bs[i])
		switch {
		case !ca.valid || !cb.valid:
			return 0, false
		case !allowLetters && (!ca.numeric || !cb.numeric):
			return 0, false
		case ca.numeric && cb.numeric:
			if ca.num != cb.num {
				return cmp.Compare(ca.num, cb.num), true
			}
		case !ca.numeric && !cb.numeric:
			if ca.letter != cb.letter {
				return cmp.Compare(ca.letter, cb.letter), true
			}
		default:
			return 0, false // numeric vs letter at the same position
		}
	}
	return 0, true
}

// fortinetTailSign decides ordering when one version is a prefix of the other:
// a numeric-zero trailing component is a no-op (7.2 == 7.2.0); any other valid
// component (a non-zero number, or a letter when allowLetters) makes the longer
// side greater, with the sign applied via dir. An invalid component — or a
// letter when allowLetters is false — is incomparable (fail safe).
func fortinetTailSign(comps []string, dir int, allowLetters bool) (int, bool) {
	for _, c := range comps {
		cc := classifyFortinetComp(c)
		switch {
		case !cc.valid, !allowLetters && !cc.numeric:
			return 0, false
		case !cc.numeric || cc.num != 0:
			return dir, true
		}
	}
	return 0, true
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
