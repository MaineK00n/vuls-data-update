package cpecriterionrange

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	stderrors "errors"
	"fmt"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	nonnumericVersion "github.com/vulsio/go-fortinet-version/nonnumeric"
	numericVersion "github.com/vulsio/go-fortinet-version/numeric"
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
	RangeTypePANOS

	// Fortinet uses one RangeType per product. RangeType.Compare receives only
	// the two version strings (no product context), so a product whose
	// versioning scheme later diverges must carry its own type to get its own
	// comparator without changing how any other product is compared — and adding
	// a type stays additive (existing products are untouched). Today every
	// product is purely numeric except the FortiSASE non-numeric scheme (which
	// Compare gives its own case); the per-product split is what lets that stay
	// true product-by-product going forward.
	RangeTypeFortinetAntivirusEngine
	RangeTypeFortinetAscenLink
	RangeTypeFortinetFortiADC
	RangeTypeFortinetFortiADCManager
	RangeTypeFortinetFortiAIOps
	RangeTypeFortinetFortiAnalyzer
	RangeTypeFortinetFortiAnalyzerBigData
	RangeTypeFortinetFortiAnalyzerCloud
	RangeTypeFortinetFortiAP
	RangeTypeFortinetFortiAPC
	RangeTypeFortinetFortiAPS
	RangeTypeFortinetFortiAPU
	RangeTypeFortinetFortiAPW2
	RangeTypeFortinetFortiAuthenticator
	RangeTypeFortinetFortiCache
	RangeTypeFortinetFortiCamera
	RangeTypeFortinetFortiClient
	RangeTypeFortinetFortiClientEnterpriseManagementServer
	RangeTypeFortinetFortiClientEnterpriseManagementServerCloud
	RangeTypeFortinetFortiConverter
	RangeTypeFortinetFortiDB
	RangeTypeFortinetFortiDDoS
	RangeTypeFortinetFortiDDoSCM
	RangeTypeFortinetFortiDDoSF
	RangeTypeFortinetFortiDeceptor
	RangeTypeFortinetFortiDLP
	RangeTypeFortinetFortiEDR
	RangeTypeFortinetFortiEDRManager
	RangeTypeFortinetFortiExtender
	RangeTypeFortinetFortiFone
	RangeTypeFortinetFortiGuest
	RangeTypeFortinetFortiIsolator
	RangeTypeFortinetFortiMail
	RangeTypeFortinetFortiManager
	RangeTypeFortinetFortiManagerCloud
	RangeTypeFortinetFortiNAC
	RangeTypeFortinetFortiNACF
	RangeTypeFortinetFortiNDR
	RangeTypeFortinetFortiOS
	RangeTypeFortinetFortiOS6k7k
	RangeTypeFortinetFortiOSIPSEngine
	RangeTypeFortinetFortiPAM
	RangeTypeFortinetFortiPortal
	RangeTypeFortinetFortiPresence
	RangeTypeFortinetFortiProxy
	RangeTypeFortinetFortiRecorder
	RangeTypeFortinetFortiSandbox
	RangeTypeFortinetFortiSandboxCloud
	RangeTypeFortinetFortiSandboxPaaS
	RangeTypeFortinetFortiSASE
	RangeTypeFortinetFortiSIEM
	RangeTypeFortinetFortiSOAR
	RangeTypeFortinetFortiSOARAgentCommunicationBridge
	RangeTypeFortinetFortiSRA
	RangeTypeFortinetFortiSwitch
	RangeTypeFortinetFortiSwitchAXFixed
	RangeTypeFortinetFortiSwitchManager
	RangeTypeFortinetFortiTester
	RangeTypeFortinetFortiTokenMobile
	RangeTypeFortinetFortiVoice
	RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop
	RangeTypeFortinetFortiWAN
	RangeTypeFortinetFortiWANManager
	RangeTypeFortinetFortiWeb
	RangeTypeFortinetFortiWebManager
	RangeTypeFortinetFortiWLC
	RangeTypeFortinetFortiWLM
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
	RangeTypeFortinetAscenLink:                                   "fortinet-ascenlink",
	RangeTypeFortinetFortiADC:                                    "fortinet-fortiadc",
	RangeTypeFortinetFortiADCManager:                             "fortinet-fortiadc_manager",
	RangeTypeFortinetFortiAIOps:                                  "fortinet-fortiaiops",
	RangeTypeFortinetFortiAnalyzer:                               "fortinet-fortianalyzer",
	RangeTypeFortinetFortiAnalyzerBigData:                        "fortinet-fortianalyzer-bigdata",
	RangeTypeFortinetFortiAnalyzerCloud:                          "fortinet-fortianalyzer_cloud",
	RangeTypeFortinetFortiAP:                                     "fortinet-fortiap",
	RangeTypeFortinetFortiAPC:                                    "fortinet-fortiap-c",
	RangeTypeFortinetFortiAPS:                                    "fortinet-fortiap-s",
	RangeTypeFortinetFortiAPU:                                    "fortinet-fortiap-u",
	RangeTypeFortinetFortiAPW2:                                   "fortinet-fortiap-w2",
	RangeTypeFortinetFortiAuthenticator:                          "fortinet-fortiauthenticator",
	RangeTypeFortinetFortiCache:                                  "fortinet-forticache",
	RangeTypeFortinetFortiCamera:                                 "fortinet-forticamera",
	RangeTypeFortinetFortiClient:                                 "fortinet-forticlient",
	RangeTypeFortinetFortiClientEnterpriseManagementServer:       "fortinet-forticlient_enterprise_management_server",
	RangeTypeFortinetFortiClientEnterpriseManagementServerCloud:  "fortinet-forticlient_enterprise_management_server_cloud",
	RangeTypeFortinetFortiConverter:                              "fortinet-forticonverter",
	RangeTypeFortinetFortiDB:                                     "fortinet-fortidb",
	RangeTypeFortinetFortiDDoS:                                   "fortinet-fortiddos",
	RangeTypeFortinetFortiDDoSCM:                                 "fortinet-fortiddos-cm",
	RangeTypeFortinetFortiDDoSF:                                  "fortinet-fortiddos-f",
	RangeTypeFortinetFortiDeceptor:                               "fortinet-fortideceptor",
	RangeTypeFortinetFortiDLP:                                    "fortinet-fortidlp",
	RangeTypeFortinetFortiEDR:                                    "fortinet-fortiedr",
	RangeTypeFortinetFortiEDRManager:                             "fortinet-fortiedr_manager",
	RangeTypeFortinetFortiExtender:                               "fortinet-fortiextender",
	RangeTypeFortinetFortiFone:                                   "fortinet-fortifone",
	RangeTypeFortinetFortiGuest:                                  "fortinet-fortiguest",
	RangeTypeFortinetFortiIsolator:                               "fortinet-fortiisolator",
	RangeTypeFortinetFortiMail:                                   "fortinet-fortimail",
	RangeTypeFortinetFortiManager:                                "fortinet-fortimanager",
	RangeTypeFortinetFortiManagerCloud:                           "fortinet-fortimanager_cloud",
	RangeTypeFortinetFortiNAC:                                    "fortinet-fortinac",
	RangeTypeFortinetFortiNACF:                                   "fortinet-fortinac-f",
	RangeTypeFortinetFortiNDR:                                    "fortinet-fortindr",
	RangeTypeFortinetFortiOS:                                     "fortinet-fortios",
	RangeTypeFortinetFortiOS6k7k:                                 "fortinet-fortios-6k7k",
	RangeTypeFortinetFortiOSIPSEngine:                            "fortinet-fortios_ips_engine",
	RangeTypeFortinetFortiPAM:                                    "fortinet-fortipam",
	RangeTypeFortinetFortiPortal:                                 "fortinet-fortiportal",
	RangeTypeFortinetFortiPresence:                               "fortinet-fortipresence",
	RangeTypeFortinetFortiProxy:                                  "fortinet-fortiproxy",
	RangeTypeFortinetFortiRecorder:                               "fortinet-fortirecorder",
	RangeTypeFortinetFortiSandbox:                                "fortinet-fortisandbox",
	RangeTypeFortinetFortiSandboxCloud:                           "fortinet-fortisandbox_cloud",
	RangeTypeFortinetFortiSandboxPaaS:                            "fortinet-fortisandbox_paas",
	RangeTypeFortinetFortiSASE:                                   "fortinet-fortisase",
	RangeTypeFortinetFortiSIEM:                                   "fortinet-fortisiem",
	RangeTypeFortinetFortiSOAR:                                   "fortinet-fortisoar",
	RangeTypeFortinetFortiSOARAgentCommunicationBridge:           "fortinet-fortisoar_agent_communication_bridge",
	RangeTypeFortinetFortiSRA:                                    "fortinet-fortisra",
	RangeTypeFortinetFortiSwitch:                                 "fortinet-fortiswitch",
	RangeTypeFortinetFortiSwitchAXFixed:                          "fortinet-fortiswitchaxfixed",
	RangeTypeFortinetFortiSwitchManager:                          "fortinet-fortiswitchmanager",
	RangeTypeFortinetFortiTester:                                 "fortinet-fortitester",
	RangeTypeFortinetFortiTokenMobile:                            "fortinet-fortitoken_mobile",
	RangeTypeFortinetFortiVoice:                                  "fortinet-fortivoice",
	RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop: "fortinet-fortivoice_cloud_unified_communications_desktop",
	RangeTypeFortinetFortiWAN:                                    "fortinet-fortiwan",
	RangeTypeFortinetFortiWANManager:                             "fortinet-fortiwan_manager",
	RangeTypeFortinetFortiWeb:                                    "fortinet-fortiweb",
	RangeTypeFortinetFortiWebManager:                             "fortinet-fortiweb_manager",
	RangeTypeFortinetFortiWLC:                                    "fortinet-fortiwlc",
	RangeTypeFortinetFortiWLM:                                    "fortinet-fortiwlm",
	RangeTypeFortinetMeru:                                        "fortinet-meru",
}

var rangeTypeByName = func() map[string]RangeType {
	m := make(map[string]RangeType, len(rangeTypeNames))
	for t, s := range rangeTypeNames {
		m[s] = t
	}
	return m
}()

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
//
// Fortinet per-product types dispatch to go-fortinet-version: FortiSASE uses
// the non-numeric (milestone-letter) scheme; every other Fortinet product uses
// the numeric scheme. The numeric comparator refuses to order a letter
// component, so a numeric product safely never matches a non-numeric version.
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
	case RangeTypeFortinetFortiSASE:
		// FortiSASE uses the non-numeric (milestone-letter) version scheme.
		// NewVersion rejecting a wrong-scheme/malformed version and Compare's
		// ErrIncomparable both surface as *CompareError, so Range.Accept treats
		// them as a safe non-match.
		va, err := nonnumericVersion.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := nonnumericVersion.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		n, err := va.Compare(vb)
		if err != nil {
			// An incomparable pair (a numeric component meeting a milestone
			// letter) is an expected, swallow-safe outcome; any other error is
			// unexpected and propagates loudly.
			if stderrors.Is(err, nonnumericVersion.ErrIncomparable) {
				return 0, &CompareError{Err: err}
			}
			return 0, err
		}
		return n, nil
	case RangeTypeFortinetAntivirusEngine,
		RangeTypeFortinetAscenLink,
		RangeTypeFortinetFortiADC,
		RangeTypeFortinetFortiADCManager,
		RangeTypeFortinetFortiAIOps,
		RangeTypeFortinetFortiAnalyzer,
		RangeTypeFortinetFortiAnalyzerBigData,
		RangeTypeFortinetFortiAnalyzerCloud,
		RangeTypeFortinetFortiAP,
		RangeTypeFortinetFortiAPC,
		RangeTypeFortinetFortiAPS,
		RangeTypeFortinetFortiAPU,
		RangeTypeFortinetFortiAPW2,
		RangeTypeFortinetFortiAuthenticator,
		RangeTypeFortinetFortiCache,
		RangeTypeFortinetFortiCamera,
		RangeTypeFortinetFortiClient,
		RangeTypeFortinetFortiClientEnterpriseManagementServer,
		RangeTypeFortinetFortiClientEnterpriseManagementServerCloud,
		RangeTypeFortinetFortiConverter,
		RangeTypeFortinetFortiDB,
		RangeTypeFortinetFortiDDoS,
		RangeTypeFortinetFortiDDoSCM,
		RangeTypeFortinetFortiDDoSF,
		RangeTypeFortinetFortiDeceptor,
		RangeTypeFortinetFortiDLP,
		RangeTypeFortinetFortiEDR,
		RangeTypeFortinetFortiEDRManager,
		RangeTypeFortinetFortiExtender,
		RangeTypeFortinetFortiFone,
		RangeTypeFortinetFortiGuest,
		RangeTypeFortinetFortiIsolator,
		RangeTypeFortinetFortiMail,
		RangeTypeFortinetFortiManager,
		RangeTypeFortinetFortiManagerCloud,
		RangeTypeFortinetFortiNAC,
		RangeTypeFortinetFortiNACF,
		RangeTypeFortinetFortiNDR,
		RangeTypeFortinetFortiOS,
		RangeTypeFortinetFortiOS6k7k,
		RangeTypeFortinetFortiOSIPSEngine,
		RangeTypeFortinetFortiPAM,
		RangeTypeFortinetFortiPortal,
		RangeTypeFortinetFortiPresence,
		RangeTypeFortinetFortiProxy,
		RangeTypeFortinetFortiRecorder,
		RangeTypeFortinetFortiSandbox,
		RangeTypeFortinetFortiSandboxCloud,
		RangeTypeFortinetFortiSandboxPaaS,
		RangeTypeFortinetFortiSIEM,
		RangeTypeFortinetFortiSOAR,
		RangeTypeFortinetFortiSOARAgentCommunicationBridge,
		RangeTypeFortinetFortiSRA,
		RangeTypeFortinetFortiSwitch,
		RangeTypeFortinetFortiSwitchAXFixed,
		RangeTypeFortinetFortiSwitchManager,
		RangeTypeFortinetFortiTester,
		RangeTypeFortinetFortiTokenMobile,
		RangeTypeFortinetFortiVoice,
		RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop,
		RangeTypeFortinetFortiWAN,
		RangeTypeFortinetFortiWANManager,
		RangeTypeFortinetFortiWeb,
		RangeTypeFortinetFortiWebManager,
		RangeTypeFortinetFortiWLC,
		RangeTypeFortinetFortiWLM,
		RangeTypeFortinetMeru:
		// Every other Fortinet product uses the purely numeric scheme. A
		// malformed or wrong-scheme version is rejected by NewVersion and wrapped
		// in *CompareError so Range.Accept treats it as a safe non-match.
		va, err := numericVersion.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := numericVersion.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		// Numeric versions are totally ordered, so Compare returns no expected
		// error; any error here is unexpected and propagates loudly.
		n, err := va.Compare(vb)
		if err != nil {
			return 0, err
		}
		return n, nil
	default:
		return 0, errors.Errorf("unsupported range type: %s", t)
	}
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
