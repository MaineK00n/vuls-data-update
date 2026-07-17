package cpecriterionrange

import (
	"cmp"
	stderrors "errors"
	"fmt"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	nonnumericVersion "github.com/vulsio/go-fortinet-version/nonnumeric"
	numericVersion "github.com/vulsio/go-fortinet-version/numeric"

	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// RangeType selects the version comparator used by CompareVersions / Accept
// (the Compare method is unrelated: it is the vocabulary ordering). Extractors
// must set it explicitly — Accept refuses to evaluate anything it cannot
// understand: the declared Unknown value quietly does not match, while a zero
// (unset — a producer-side bug) or out-of-vocabulary Type is reported as a
// non-fatal *warning.UnevaluableError for the criterion layer to record, so a
// forgotten Type surfaces instead of silently matching. The `type` JSON tag
// carries `omitempty`, so a zero value is omitted from output rather than
// written as "unknown"; an explicitly-set Unknown is serialized as "unknown".
//
// It is a string so that unmarshaling never validates against the known set:
// data produced by a newer vuls-data-update (carrying range types this build
// does not know) still round-trips losslessly. CompareVersions answers such
// with *UnsupportedRangeTypeError wrapped in *CompareError, which Accept
// degrades to a safe non-match, so an old binary skips the criterion instead
// of failing detection.
//
// Independent from versioncriterion/affected/range.RangeType: only types
// meaningful for CPE-side matching belong here. Add new comparators (e.g.
// cisco IOS train versions) as needed.
type RangeType string

const (
	RangeTypeVersion RangeType = "version"
	RangeTypeSEMVER  RangeType = "semver"
	RangeTypePANOS   RangeType = "pan-os"

	// Fortinet uses one RangeType per product. RangeType.CompareVersions receives only
	// the two version strings (no product context), so a product whose
	// versioning scheme later diverges must carry its own type to get its own
	// comparator without changing how any other product is compared — and adding
	// a type stays additive (existing products are untouched). Today every
	// product is purely numeric except the FortiSASE non-numeric scheme (which
	// Compare gives its own case); the per-product split is what lets that stay
	// true product-by-product going forward.
	RangeTypeFortinetAntivirusEngine                             RangeType = "fortinet-antivirus_engine"
	RangeTypeFortinetAscenLink                                   RangeType = "fortinet-ascenlink"
	RangeTypeFortinetFortiADC                                    RangeType = "fortinet-fortiadc"
	RangeTypeFortinetFortiADCManager                             RangeType = "fortinet-fortiadc_manager"
	RangeTypeFortinetFortiAIOps                                  RangeType = "fortinet-fortiaiops"
	RangeTypeFortinetFortiAnalyzer                               RangeType = "fortinet-fortianalyzer"
	RangeTypeFortinetFortiAnalyzerBigData                        RangeType = "fortinet-fortianalyzer-bigdata"
	RangeTypeFortinetFortiAnalyzerCloud                          RangeType = "fortinet-fortianalyzer_cloud"
	RangeTypeFortinetFortiAP                                     RangeType = "fortinet-fortiap"
	RangeTypeFortinetFortiAPC                                    RangeType = "fortinet-fortiap-c"
	RangeTypeFortinetFortiAPS                                    RangeType = "fortinet-fortiap-s"
	RangeTypeFortinetFortiAPU                                    RangeType = "fortinet-fortiap-u"
	RangeTypeFortinetFortiAPW2                                   RangeType = "fortinet-fortiap-w2"
	RangeTypeFortinetFortiAuthenticator                          RangeType = "fortinet-fortiauthenticator"
	RangeTypeFortinetFortiCache                                  RangeType = "fortinet-forticache"
	RangeTypeFortinetFortiCamera                                 RangeType = "fortinet-forticamera"
	RangeTypeFortinetFortiClient                                 RangeType = "fortinet-forticlient"
	RangeTypeFortinetFortiClientEnterpriseManagementServer       RangeType = "fortinet-forticlient_enterprise_management_server"
	RangeTypeFortinetFortiClientEnterpriseManagementServerCloud  RangeType = "fortinet-forticlient_enterprise_management_server_cloud"
	RangeTypeFortinetFortiConverter                              RangeType = "fortinet-forticonverter"
	RangeTypeFortinetFortiDB                                     RangeType = "fortinet-fortidb"
	RangeTypeFortinetFortiDDoS                                   RangeType = "fortinet-fortiddos"
	RangeTypeFortinetFortiDDoSCM                                 RangeType = "fortinet-fortiddos-cm"
	RangeTypeFortinetFortiDDoSF                                  RangeType = "fortinet-fortiddos-f"
	RangeTypeFortinetFortiDeceptor                               RangeType = "fortinet-fortideceptor"
	RangeTypeFortinetFortiDLP                                    RangeType = "fortinet-fortidlp"
	RangeTypeFortinetFortiEDR                                    RangeType = "fortinet-fortiedr"
	RangeTypeFortinetFortiEDRManager                             RangeType = "fortinet-fortiedr_manager"
	RangeTypeFortinetFortiExtender                               RangeType = "fortinet-fortiextender"
	RangeTypeFortinetFortiFone                                   RangeType = "fortinet-fortifone"
	RangeTypeFortinetFortiGuest                                  RangeType = "fortinet-fortiguest"
	RangeTypeFortinetFortiIsolator                               RangeType = "fortinet-fortiisolator"
	RangeTypeFortinetFortiMail                                   RangeType = "fortinet-fortimail"
	RangeTypeFortinetFortiManager                                RangeType = "fortinet-fortimanager"
	RangeTypeFortinetFortiManagerCloud                           RangeType = "fortinet-fortimanager_cloud"
	RangeTypeFortinetFortiNAC                                    RangeType = "fortinet-fortinac"
	RangeTypeFortinetFortiNACF                                   RangeType = "fortinet-fortinac-f"
	RangeTypeFortinetFortiNDR                                    RangeType = "fortinet-fortindr"
	RangeTypeFortinetFortiOS                                     RangeType = "fortinet-fortios"
	RangeTypeFortinetFortiOS6k7k                                 RangeType = "fortinet-fortios-6k7k"
	RangeTypeFortinetFortiOSIPSEngine                            RangeType = "fortinet-fortios_ips_engine"
	RangeTypeFortinetFortiPAM                                    RangeType = "fortinet-fortipam"
	RangeTypeFortinetFortiPortal                                 RangeType = "fortinet-fortiportal"
	RangeTypeFortinetFortiPresence                               RangeType = "fortinet-fortipresence"
	RangeTypeFortinetFortiProxy                                  RangeType = "fortinet-fortiproxy"
	RangeTypeFortinetFortiRecorder                               RangeType = "fortinet-fortirecorder"
	RangeTypeFortinetFortiSandbox                                RangeType = "fortinet-fortisandbox"
	RangeTypeFortinetFortiSandboxCloud                           RangeType = "fortinet-fortisandbox_cloud"
	RangeTypeFortinetFortiSandboxPaaS                            RangeType = "fortinet-fortisandbox_paas"
	RangeTypeFortinetFortiSASE                                   RangeType = "fortinet-fortisase"
	RangeTypeFortinetFortiSIEM                                   RangeType = "fortinet-fortisiem"
	RangeTypeFortinetFortiSOAR                                   RangeType = "fortinet-fortisoar"
	RangeTypeFortinetFortiSOARAgentCommunicationBridge           RangeType = "fortinet-fortisoar_agent_communication_bridge"
	RangeTypeFortinetFortiSRA                                    RangeType = "fortinet-fortisra"
	RangeTypeFortinetFortiSwitch                                 RangeType = "fortinet-fortiswitch"
	RangeTypeFortinetFortiSwitchAXFixed                          RangeType = "fortinet-fortiswitchaxfixed"
	RangeTypeFortinetFortiSwitchManager                          RangeType = "fortinet-fortiswitchmanager"
	RangeTypeFortinetFortiTester                                 RangeType = "fortinet-fortitester"
	RangeTypeFortinetFortiTokenMobile                            RangeType = "fortinet-fortitoken_mobile"
	RangeTypeFortinetFortiVoice                                  RangeType = "fortinet-fortivoice"
	RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop RangeType = "fortinet-fortivoice_cloud_unified_communications_desktop"
	RangeTypeFortinetFortiWAN                                    RangeType = "fortinet-fortiwan"
	RangeTypeFortinetFortiWANManager                             RangeType = "fortinet-fortiwan_manager"
	RangeTypeFortinetFortiWeb                                    RangeType = "fortinet-fortiweb"
	RangeTypeFortinetFortiWebManager                             RangeType = "fortinet-fortiweb_manager"
	RangeTypeFortinetFortiWLC                                    RangeType = "fortinet-fortiwlc"
	RangeTypeFortinetFortiWLM                                    RangeType = "fortinet-fortiwlm"
	RangeTypeFortinetMeru                                        RangeType = "fortinet-meru"

	RangeTypeUnknown RangeType = "unknown"
)

// RangeTypes returns every RangeType this build knows, in declaration order.
// Consumers (vuls2, vuls0) diff this list against a newer vuls-data-update in
// CI to detect enum additions that require a dependency bump. The known set
// must be append-only: removing or renaming a value would leave already
// extracted data undetectable by builds that follow the removal.
func RangeTypes() []RangeType {
	return []RangeType{
		RangeTypeVersion,
		RangeTypeSEMVER,
		RangeTypePANOS,
		RangeTypeFortinetAntivirusEngine,
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
		RangeTypeFortinetFortiSASE,
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
		RangeTypeFortinetMeru,
		RangeTypeUnknown,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// RangeTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t RangeType) Compare(u RangeType) int {
	return vocabulary.Compare(t, u)
}

var vocabulary = enum.NewVocabulary(RangeTypes())

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
		x.Type.Compare(y.Type),
		cmp.Compare(x.GreaterEqual, y.GreaterEqual),
		cmp.Compare(x.GreaterThan, y.GreaterThan),
		cmp.Compare(x.LessEqual, y.LessEqual),
		cmp.Compare(x.LessThan, y.LessThan),
	)
}

// CompareError wraps the failure modes RangeType.CompareVersions can raise
// so that callers can classify them. Mirrors versioncriterion/affected/range's
// pattern: every failure CompareVersions raises — parse errors, unevaluable
// types, comparator-internal errors — is wrapped in CompareError so that
// Accept can always degrade it to a safe non-match.
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

// UnsupportedRangeTypeError is wrapped in a *CompareError when
// CompareVersions is called with a RangeType outside this build's vocabulary: a value produced
// by a newer vuls-data-update read by an older binary, or the zero value
// (unset — a producer-side bug; check the RangeType field to tell the two
// apart). Only the declared "unknown" vocabulary value classifies as
// ErrRangeTypeUnknown instead. Callers that need to tell these anomalies
// apart from ordinary parse failures can errors.As for this type through
// the CompareError chain.
type UnsupportedRangeTypeError struct {
	RangeType RangeType
}

func (e *UnsupportedRangeTypeError) Error() string {
	return fmt.Sprintf("unsupported range type %q", string(e.RangeType))
}

// ErrRangeTypeUnknown is wrapped in a CompareError when CompareVersions is
// called with a Type that cannot evaluate any version.
var ErrRangeTypeUnknown = errors.New("unknown range type")

// CompareVersions returns an integer comparing v1 and v2 under the comparator
// selected by t (semantics match hashicorp version.Version.Compare):
// negative for v1 < v2, zero for equal, positive for v1 > v2.
//
// Parse failures (either side) are wrapped in *CompareError so that
// detect-time callers can swallow them gracefully. A RangeType with no
// comparator likewise wraps in *CompareError: the declared Unknown value
// carries ErrRangeTypeUnknown, while anything outside the vocabulary — the
// zero value (unset) or a value this build does not know (data from a newer
// vuls-data-update) — carries *UnsupportedRangeTypeError.
// Comparator-internal failures (e.g. an incomparable non-numeric pair) wrap
// in *CompareError as well — every error this function raises classifies as
// *CompareError, so Accept can always degrade it to a safe non-match.
//
// Fortinet per-product types dispatch to go-fortinet-version: FortiSASE uses
// the non-numeric (milestone-letter) scheme; every other Fortinet product uses
// the numeric scheme. The numeric comparator refuses to order a letter
// component, so a numeric product safely never matches a non-numeric version.
func (t RangeType) CompareVersions(v1, v2 string) (int, error) {
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
			// letter) is the expected error here; wrap it — like every other
			// failure path in this function — in *CompareError so Range.Accept
			// degrades to a safe non-match instead of aborting detection.
			return 0, &CompareError{Err: err}
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
		// Numeric versions are totally ordered, so a comparison error is not
		// expected here. Should one occur, wrap it in *CompareError like every
		// other failure path in this function so Range.Accept degrades to a safe
		// non-match instead of aborting detection.
		n, err := va.Compare(vb)
		if err != nil {
			return 0, &CompareError{Err: err}
		}
		return n, nil
	case RangeTypeUnknown:
		// The declared "unknown" vocabulary value is normal data; it quietly
		// cannot evaluate.
		return 0, &CompareError{Err: ErrRangeTypeUnknown}
	default:
		// Everything outside the vocabulary — the zero value (unset, a
		// producer-side bug) or a value this build does not know (data from
		// a newer vuls-data-update) — is an anomaly worth surfacing, so it
		// classifies as *UnsupportedRangeTypeError (the two are told apart
		// via its RangeType field). Wrapping in *CompareError still lets
		// Range.Accept degrade to a safe non-match instead of aborting
		// detection on an old binary.
		return 0, &CompareError{Err: &UnsupportedRangeTypeError{RangeType: t}}
	}
}

// Accept returns true when v satisfies every non-empty bound on r, comparing
// via r.Type.CompareVersions. An endpoint-less Range (all four bound strings
// unset) expresses nothing — "no version constraint" is Criterion.Range ==
// nil — and reports a non-fatal *warning.UnevaluableError (empty-range).
//
// Bound comparisons that cannot be evaluated split two ways: a range type
// this build has no comparator for (*UnsupportedRangeTypeError through the
// *CompareError chain) also reports a non-fatal *warning.UnevaluableError so
// the criterion layer can record it, while the remaining *CompareError
// failures (parse failures on either bound or query, the Unknown-type
// sentinel) are swallowed as graceful non-matches so a detect run against
// malformed scan input does not crash. Every error CompareVersions currently
// raises classifies as *CompareError; the propagation branch below is
// defensive, for error kinds a future comparator might introduce. Mirrors
// versioncriterion/affected.Accept.
func (r Range) Accept(v string) (bool, error) {
	if r.GreaterEqual == "" && r.GreaterThan == "" && r.LessEqual == "" && r.LessThan == "" {
		// A Range with no endpoints expresses nothing and cannot declare a
		// match: "no version constraint" is expressed by Criterion.Range ==
		// nil, which never reaches here, so this is malformed data (schema
		// validation is the hard gate) or a newer range type whose
		// constraints live in JSON fields this build's unmarshal drops.
		// Report it as a non-fatal empty-range warning rather than aborting
		// detection in the field.
		return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange, Cause: string(r.Type)}}
	}

	type bound struct {
		label string
		s     string
		// reject reports whether the CompareVersions(bound, v) sign should
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
		n, err := r.Type.CompareVersions(b.s, v)
		if err != nil {
			if ue, ok := stderrors.AsType[*UnsupportedRangeTypeError](err); ok {
				return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: string(ue.RangeType)}}
			}
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
