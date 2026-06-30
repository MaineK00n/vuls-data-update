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

func (t RangeType) String() string {
	switch t {
	case RangeTypeVersion:
		return "version"
	case RangeTypeSEMVER:
		return "semver"
	case RangeTypePANOS:
		return "pan-os"
	case RangeTypeFortinetAntivirusEngine:
		return "fortinet-antivirus_engine"
	case RangeTypeFortinetAscenLink:
		return "fortinet-ascenlink"
	case RangeTypeFortinetFortiADC:
		return "fortinet-fortiadc"
	case RangeTypeFortinetFortiADCManager:
		return "fortinet-fortiadc_manager"
	case RangeTypeFortinetFortiAIOps:
		return "fortinet-fortiaiops"
	case RangeTypeFortinetFortiAnalyzer:
		return "fortinet-fortianalyzer"
	case RangeTypeFortinetFortiAnalyzerBigData:
		return "fortinet-fortianalyzer-bigdata"
	case RangeTypeFortinetFortiAnalyzerCloud:
		return "fortinet-fortianalyzer_cloud"
	case RangeTypeFortinetFortiAP:
		return "fortinet-fortiap"
	case RangeTypeFortinetFortiAPC:
		return "fortinet-fortiap-c"
	case RangeTypeFortinetFortiAPS:
		return "fortinet-fortiap-s"
	case RangeTypeFortinetFortiAPU:
		return "fortinet-fortiap-u"
	case RangeTypeFortinetFortiAPW2:
		return "fortinet-fortiap-w2"
	case RangeTypeFortinetFortiAuthenticator:
		return "fortinet-fortiauthenticator"
	case RangeTypeFortinetFortiCache:
		return "fortinet-forticache"
	case RangeTypeFortinetFortiCamera:
		return "fortinet-forticamera"
	case RangeTypeFortinetFortiClient:
		return "fortinet-forticlient"
	case RangeTypeFortinetFortiClientEnterpriseManagementServer:
		return "fortinet-forticlient_enterprise_management_server"
	case RangeTypeFortinetFortiClientEnterpriseManagementServerCloud:
		return "fortinet-forticlient_enterprise_management_server_cloud"
	case RangeTypeFortinetFortiConverter:
		return "fortinet-forticonverter"
	case RangeTypeFortinetFortiDB:
		return "fortinet-fortidb"
	case RangeTypeFortinetFortiDDoS:
		return "fortinet-fortiddos"
	case RangeTypeFortinetFortiDDoSCM:
		return "fortinet-fortiddos-cm"
	case RangeTypeFortinetFortiDDoSF:
		return "fortinet-fortiddos-f"
	case RangeTypeFortinetFortiDeceptor:
		return "fortinet-fortideceptor"
	case RangeTypeFortinetFortiDLP:
		return "fortinet-fortidlp"
	case RangeTypeFortinetFortiEDR:
		return "fortinet-fortiedr"
	case RangeTypeFortinetFortiEDRManager:
		return "fortinet-fortiedr_manager"
	case RangeTypeFortinetFortiExtender:
		return "fortinet-fortiextender"
	case RangeTypeFortinetFortiFone:
		return "fortinet-fortifone"
	case RangeTypeFortinetFortiGuest:
		return "fortinet-fortiguest"
	case RangeTypeFortinetFortiIsolator:
		return "fortinet-fortiisolator"
	case RangeTypeFortinetFortiMail:
		return "fortinet-fortimail"
	case RangeTypeFortinetFortiManager:
		return "fortinet-fortimanager"
	case RangeTypeFortinetFortiManagerCloud:
		return "fortinet-fortimanager_cloud"
	case RangeTypeFortinetFortiNAC:
		return "fortinet-fortinac"
	case RangeTypeFortinetFortiNACF:
		return "fortinet-fortinac-f"
	case RangeTypeFortinetFortiNDR:
		return "fortinet-fortindr"
	case RangeTypeFortinetFortiOS:
		return "fortinet-fortios"
	case RangeTypeFortinetFortiOS6k7k:
		return "fortinet-fortios-6k7k"
	case RangeTypeFortinetFortiOSIPSEngine:
		return "fortinet-fortios_ips_engine"
	case RangeTypeFortinetFortiPAM:
		return "fortinet-fortipam"
	case RangeTypeFortinetFortiPortal:
		return "fortinet-fortiportal"
	case RangeTypeFortinetFortiPresence:
		return "fortinet-fortipresence"
	case RangeTypeFortinetFortiProxy:
		return "fortinet-fortiproxy"
	case RangeTypeFortinetFortiRecorder:
		return "fortinet-fortirecorder"
	case RangeTypeFortinetFortiSandbox:
		return "fortinet-fortisandbox"
	case RangeTypeFortinetFortiSandboxCloud:
		return "fortinet-fortisandbox_cloud"
	case RangeTypeFortinetFortiSandboxPaaS:
		return "fortinet-fortisandbox_paas"
	case RangeTypeFortinetFortiSASE:
		return "fortinet-fortisase"
	case RangeTypeFortinetFortiSIEM:
		return "fortinet-fortisiem"
	case RangeTypeFortinetFortiSOAR:
		return "fortinet-fortisoar"
	case RangeTypeFortinetFortiSOARAgentCommunicationBridge:
		return "fortinet-fortisoar_agent_communication_bridge"
	case RangeTypeFortinetFortiSRA:
		return "fortinet-fortisra"
	case RangeTypeFortinetFortiSwitch:
		return "fortinet-fortiswitch"
	case RangeTypeFortinetFortiSwitchAXFixed:
		return "fortinet-fortiswitchaxfixed"
	case RangeTypeFortinetFortiSwitchManager:
		return "fortinet-fortiswitchmanager"
	case RangeTypeFortinetFortiTester:
		return "fortinet-fortitester"
	case RangeTypeFortinetFortiTokenMobile:
		return "fortinet-fortitoken_mobile"
	case RangeTypeFortinetFortiVoice:
		return "fortinet-fortivoice"
	case RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop:
		return "fortinet-fortivoice_cloud_unified_communications_desktop"
	case RangeTypeFortinetFortiWAN:
		return "fortinet-fortiwan"
	case RangeTypeFortinetFortiWANManager:
		return "fortinet-fortiwan_manager"
	case RangeTypeFortinetFortiWeb:
		return "fortinet-fortiweb"
	case RangeTypeFortinetFortiWebManager:
		return "fortinet-fortiweb_manager"
	case RangeTypeFortinetFortiWLC:
		return "fortinet-fortiwlc"
	case RangeTypeFortinetFortiWLM:
		return "fortinet-fortiwlm"
	case RangeTypeFortinetMeru:
		return "fortinet-meru"
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
	case "pan-os":
		*t = RangeTypePANOS
	case "fortinet-antivirus_engine":
		*t = RangeTypeFortinetAntivirusEngine
	case "fortinet-ascenlink":
		*t = RangeTypeFortinetAscenLink
	case "fortinet-fortiadc":
		*t = RangeTypeFortinetFortiADC
	case "fortinet-fortiadc_manager":
		*t = RangeTypeFortinetFortiADCManager
	case "fortinet-fortiaiops":
		*t = RangeTypeFortinetFortiAIOps
	case "fortinet-fortianalyzer":
		*t = RangeTypeFortinetFortiAnalyzer
	case "fortinet-fortianalyzer-bigdata":
		*t = RangeTypeFortinetFortiAnalyzerBigData
	case "fortinet-fortianalyzer_cloud":
		*t = RangeTypeFortinetFortiAnalyzerCloud
	case "fortinet-fortiap":
		*t = RangeTypeFortinetFortiAP
	case "fortinet-fortiap-c":
		*t = RangeTypeFortinetFortiAPC
	case "fortinet-fortiap-s":
		*t = RangeTypeFortinetFortiAPS
	case "fortinet-fortiap-u":
		*t = RangeTypeFortinetFortiAPU
	case "fortinet-fortiap-w2":
		*t = RangeTypeFortinetFortiAPW2
	case "fortinet-fortiauthenticator":
		*t = RangeTypeFortinetFortiAuthenticator
	case "fortinet-forticache":
		*t = RangeTypeFortinetFortiCache
	case "fortinet-forticamera":
		*t = RangeTypeFortinetFortiCamera
	case "fortinet-forticlient":
		*t = RangeTypeFortinetFortiClient
	case "fortinet-forticlient_enterprise_management_server":
		*t = RangeTypeFortinetFortiClientEnterpriseManagementServer
	case "fortinet-forticlient_enterprise_management_server_cloud":
		*t = RangeTypeFortinetFortiClientEnterpriseManagementServerCloud
	case "fortinet-forticonverter":
		*t = RangeTypeFortinetFortiConverter
	case "fortinet-fortidb":
		*t = RangeTypeFortinetFortiDB
	case "fortinet-fortiddos":
		*t = RangeTypeFortinetFortiDDoS
	case "fortinet-fortiddos-cm":
		*t = RangeTypeFortinetFortiDDoSCM
	case "fortinet-fortiddos-f":
		*t = RangeTypeFortinetFortiDDoSF
	case "fortinet-fortideceptor":
		*t = RangeTypeFortinetFortiDeceptor
	case "fortinet-fortidlp":
		*t = RangeTypeFortinetFortiDLP
	case "fortinet-fortiedr":
		*t = RangeTypeFortinetFortiEDR
	case "fortinet-fortiedr_manager":
		*t = RangeTypeFortinetFortiEDRManager
	case "fortinet-fortiextender":
		*t = RangeTypeFortinetFortiExtender
	case "fortinet-fortifone":
		*t = RangeTypeFortinetFortiFone
	case "fortinet-fortiguest":
		*t = RangeTypeFortinetFortiGuest
	case "fortinet-fortiisolator":
		*t = RangeTypeFortinetFortiIsolator
	case "fortinet-fortimail":
		*t = RangeTypeFortinetFortiMail
	case "fortinet-fortimanager":
		*t = RangeTypeFortinetFortiManager
	case "fortinet-fortimanager_cloud":
		*t = RangeTypeFortinetFortiManagerCloud
	case "fortinet-fortinac":
		*t = RangeTypeFortinetFortiNAC
	case "fortinet-fortinac-f":
		*t = RangeTypeFortinetFortiNACF
	case "fortinet-fortindr":
		*t = RangeTypeFortinetFortiNDR
	case "fortinet-fortios":
		*t = RangeTypeFortinetFortiOS
	case "fortinet-fortios-6k7k":
		*t = RangeTypeFortinetFortiOS6k7k
	case "fortinet-fortios_ips_engine":
		*t = RangeTypeFortinetFortiOSIPSEngine
	case "fortinet-fortipam":
		*t = RangeTypeFortinetFortiPAM
	case "fortinet-fortiportal":
		*t = RangeTypeFortinetFortiPortal
	case "fortinet-fortipresence":
		*t = RangeTypeFortinetFortiPresence
	case "fortinet-fortiproxy":
		*t = RangeTypeFortinetFortiProxy
	case "fortinet-fortirecorder":
		*t = RangeTypeFortinetFortiRecorder
	case "fortinet-fortisandbox":
		*t = RangeTypeFortinetFortiSandbox
	case "fortinet-fortisandbox_cloud":
		*t = RangeTypeFortinetFortiSandboxCloud
	case "fortinet-fortisandbox_paas":
		*t = RangeTypeFortinetFortiSandboxPaaS
	case "fortinet-fortisase":
		*t = RangeTypeFortinetFortiSASE
	case "fortinet-fortisiem":
		*t = RangeTypeFortinetFortiSIEM
	case "fortinet-fortisoar":
		*t = RangeTypeFortinetFortiSOAR
	case "fortinet-fortisoar_agent_communication_bridge":
		*t = RangeTypeFortinetFortiSOARAgentCommunicationBridge
	case "fortinet-fortisra":
		*t = RangeTypeFortinetFortiSRA
	case "fortinet-fortiswitch":
		*t = RangeTypeFortinetFortiSwitch
	case "fortinet-fortiswitchaxfixed":
		*t = RangeTypeFortinetFortiSwitchAXFixed
	case "fortinet-fortiswitchmanager":
		*t = RangeTypeFortinetFortiSwitchManager
	case "fortinet-fortitester":
		*t = RangeTypeFortinetFortiTester
	case "fortinet-fortitoken_mobile":
		*t = RangeTypeFortinetFortiTokenMobile
	case "fortinet-fortivoice":
		*t = RangeTypeFortinetFortiVoice
	case "fortinet-fortivoice_cloud_unified_communications_desktop":
		*t = RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop
	case "fortinet-fortiwan":
		*t = RangeTypeFortinetFortiWAN
	case "fortinet-fortiwan_manager":
		*t = RangeTypeFortinetFortiWANManager
	case "fortinet-fortiweb":
		*t = RangeTypeFortinetFortiWeb
	case "fortinet-fortiweb_manager":
		*t = RangeTypeFortinetFortiWebManager
	case "fortinet-fortiwlc":
		*t = RangeTypeFortinetFortiWLC
	case "fortinet-fortiwlm":
		*t = RangeTypeFortinetFortiWLM
	case "fortinet-meru":
		*t = RangeTypeFortinetMeru
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
	case "pan-os":
		rt = RangeTypePANOS
	case "fortinet-antivirus_engine":
		rt = RangeTypeFortinetAntivirusEngine
	case "fortinet-ascenlink":
		rt = RangeTypeFortinetAscenLink
	case "fortinet-fortiadc":
		rt = RangeTypeFortinetFortiADC
	case "fortinet-fortiadc_manager":
		rt = RangeTypeFortinetFortiADCManager
	case "fortinet-fortiaiops":
		rt = RangeTypeFortinetFortiAIOps
	case "fortinet-fortianalyzer":
		rt = RangeTypeFortinetFortiAnalyzer
	case "fortinet-fortianalyzer-bigdata":
		rt = RangeTypeFortinetFortiAnalyzerBigData
	case "fortinet-fortianalyzer_cloud":
		rt = RangeTypeFortinetFortiAnalyzerCloud
	case "fortinet-fortiap":
		rt = RangeTypeFortinetFortiAP
	case "fortinet-fortiap-c":
		rt = RangeTypeFortinetFortiAPC
	case "fortinet-fortiap-s":
		rt = RangeTypeFortinetFortiAPS
	case "fortinet-fortiap-u":
		rt = RangeTypeFortinetFortiAPU
	case "fortinet-fortiap-w2":
		rt = RangeTypeFortinetFortiAPW2
	case "fortinet-fortiauthenticator":
		rt = RangeTypeFortinetFortiAuthenticator
	case "fortinet-forticache":
		rt = RangeTypeFortinetFortiCache
	case "fortinet-forticamera":
		rt = RangeTypeFortinetFortiCamera
	case "fortinet-forticlient":
		rt = RangeTypeFortinetFortiClient
	case "fortinet-forticlient_enterprise_management_server":
		rt = RangeTypeFortinetFortiClientEnterpriseManagementServer
	case "fortinet-forticlient_enterprise_management_server_cloud":
		rt = RangeTypeFortinetFortiClientEnterpriseManagementServerCloud
	case "fortinet-forticonverter":
		rt = RangeTypeFortinetFortiConverter
	case "fortinet-fortidb":
		rt = RangeTypeFortinetFortiDB
	case "fortinet-fortiddos":
		rt = RangeTypeFortinetFortiDDoS
	case "fortinet-fortiddos-cm":
		rt = RangeTypeFortinetFortiDDoSCM
	case "fortinet-fortiddos-f":
		rt = RangeTypeFortinetFortiDDoSF
	case "fortinet-fortideceptor":
		rt = RangeTypeFortinetFortiDeceptor
	case "fortinet-fortidlp":
		rt = RangeTypeFortinetFortiDLP
	case "fortinet-fortiedr":
		rt = RangeTypeFortinetFortiEDR
	case "fortinet-fortiedr_manager":
		rt = RangeTypeFortinetFortiEDRManager
	case "fortinet-fortiextender":
		rt = RangeTypeFortinetFortiExtender
	case "fortinet-fortifone":
		rt = RangeTypeFortinetFortiFone
	case "fortinet-fortiguest":
		rt = RangeTypeFortinetFortiGuest
	case "fortinet-fortiisolator":
		rt = RangeTypeFortinetFortiIsolator
	case "fortinet-fortimail":
		rt = RangeTypeFortinetFortiMail
	case "fortinet-fortimanager":
		rt = RangeTypeFortinetFortiManager
	case "fortinet-fortimanager_cloud":
		rt = RangeTypeFortinetFortiManagerCloud
	case "fortinet-fortinac":
		rt = RangeTypeFortinetFortiNAC
	case "fortinet-fortinac-f":
		rt = RangeTypeFortinetFortiNACF
	case "fortinet-fortindr":
		rt = RangeTypeFortinetFortiNDR
	case "fortinet-fortios":
		rt = RangeTypeFortinetFortiOS
	case "fortinet-fortios-6k7k":
		rt = RangeTypeFortinetFortiOS6k7k
	case "fortinet-fortios_ips_engine":
		rt = RangeTypeFortinetFortiOSIPSEngine
	case "fortinet-fortipam":
		rt = RangeTypeFortinetFortiPAM
	case "fortinet-fortiportal":
		rt = RangeTypeFortinetFortiPortal
	case "fortinet-fortipresence":
		rt = RangeTypeFortinetFortiPresence
	case "fortinet-fortiproxy":
		rt = RangeTypeFortinetFortiProxy
	case "fortinet-fortirecorder":
		rt = RangeTypeFortinetFortiRecorder
	case "fortinet-fortisandbox":
		rt = RangeTypeFortinetFortiSandbox
	case "fortinet-fortisandbox_cloud":
		rt = RangeTypeFortinetFortiSandboxCloud
	case "fortinet-fortisandbox_paas":
		rt = RangeTypeFortinetFortiSandboxPaaS
	case "fortinet-fortisase":
		rt = RangeTypeFortinetFortiSASE
	case "fortinet-fortisiem":
		rt = RangeTypeFortinetFortiSIEM
	case "fortinet-fortisoar":
		rt = RangeTypeFortinetFortiSOAR
	case "fortinet-fortisoar_agent_communication_bridge":
		rt = RangeTypeFortinetFortiSOARAgentCommunicationBridge
	case "fortinet-fortisra":
		rt = RangeTypeFortinetFortiSRA
	case "fortinet-fortiswitch":
		rt = RangeTypeFortinetFortiSwitch
	case "fortinet-fortiswitchaxfixed":
		rt = RangeTypeFortinetFortiSwitchAXFixed
	case "fortinet-fortiswitchmanager":
		rt = RangeTypeFortinetFortiSwitchManager
	case "fortinet-fortitester":
		rt = RangeTypeFortinetFortiTester
	case "fortinet-fortitoken_mobile":
		rt = RangeTypeFortinetFortiTokenMobile
	case "fortinet-fortivoice":
		rt = RangeTypeFortinetFortiVoice
	case "fortinet-fortivoice_cloud_unified_communications_desktop":
		rt = RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop
	case "fortinet-fortiwan":
		rt = RangeTypeFortinetFortiWAN
	case "fortinet-fortiwan_manager":
		rt = RangeTypeFortinetFortiWANManager
	case "fortinet-fortiweb":
		rt = RangeTypeFortinetFortiWeb
	case "fortinet-fortiweb_manager":
		rt = RangeTypeFortinetFortiWebManager
	case "fortinet-fortiwlc":
		rt = RangeTypeFortinetFortiWLC
	case "fortinet-fortiwlm":
		rt = RangeTypeFortinetFortiWLM
	case "fortinet-meru":
		rt = RangeTypeFortinetMeru
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
