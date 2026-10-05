// Maps a Fortinet product name (as it appears in CSAF product nodes and CVRF
// "Product Name" branches) to its CPE 2.3 formatted string (wildcard
// version) and its per-product cpecriterion range type. A name missing here
// makes the CSAF/CVRF extractor hard-error on the affected product rather
// than silently drop it, so add new Fortinet products here.
//
// The CPE is the one Fortinet itself assigns, as CNA, in its CVE records
// (containers.cna.affected[].cpes on cve.org), not the one NVD assigns when it
// enriches the CVE: Fortinet names each product apart (FortiClientWindows /
// FortiClientMac, FortiSOAR PaaS / on-premise) where NVD folds them into one
// product told apart by target_sw or not at all. As of 2026-10, Fortinet's
// CPEs follow one rule — vendor "fortinet", product the product name
// lowercased with its spaces removed ("FortiSOAR on-premise" ->
// "fortisoaron-premise"), target_sw never set — and give each product one
// part across every record (FortiOS, FortiAnalyzer, FortiManager, FortiDDoS,
// FortiDDoS-F and FortiPAM "o"; FortiADC and FortiADCManager "h"; the rest
// "a"). The one exception to the naming is "FortiPAM Chrome Extension",
// which CVE-2026-84388 names "fortipam_chrome_extension", spaces turned into
// underscores: take a product's slug from its records whenever they give
// one, and derive it only when none does. Each product maps to that one
// CPE, whatever the advisory.
//
// For a product none of Fortinet's CVE records give a CPE yet, the CPE's
// product component (the slug) follows the same rule, and its part is NVD's
// where NVD has the product. Otherwise the part is set from what the
// advisories scope: "a" for software and services, "o" where they scope
// firmware versions (FortiFone: "FortiFone versions 3.0.11 and below"), "h"
// where they scope device models (FortiBalancer: "FortiBalancer 400, 1000,
// 2000 and 3000. All software versions are affected."). The range types keep
// the names they were published under, which follow earlier CPEs.
package product

import (
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// productInfo is a product's CPE and its per-product range type. Each product
// carries its own range type so a product whose version scheme later diverges
// gets its own comparator without affecting any other (see cpecriterion/range).
// twoComponentVersions marks products for which a two-component token ("X.Y",
// e.g. IPS Engine "7.166") is itself a concrete release rather than a train;
// for them only a bare major is a train (see IsExactVersion). It does NOT
// claim every release of the product has two components: AV Engine also has
// older three-component exacts ("4.4.54"), which the marked rule likewise
// classifies exact (it accepts any token with one or more dots). Mark a
// product ONLY with corpus evidence that no
// three-component release exists under any of its two-component tokens:
// FortiSandbox Cloud/PaaS look two-component in some advisories ("23.4",
// "5.0") but other advisories enumerate build-suffixed releases under those
// very tokens ("23.4.4350", "5.0.4"), so their two-component tokens are
// trains and they must NOT be marked.
type productInfo struct {
	cpe                  string
	rangeType            ccRangeTypes.RangeType
	twoComponentVersions bool
}

var nameToProduct = map[string]productInfo{
	"AV Engine":                       {cpe: "cpe:2.3:a:fortinet:avengine:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetAntivirusEngine, twoComponentVersions: true},
	"AscenLink":                       {cpe: "cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetAscenLink},
	"Connect":                         {cpe: "cpe:2.3:a:fortinet:connect:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetConnect},
	"FSSO":                            {cpe: "cpe:2.3:a:fortinet:fsso:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFSSO},
	"FSSO CA":                         {cpe: "cpe:2.3:a:fortinet:fssoca:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFSSOCA},
	"FortiADC":                        {cpe: "cpe:2.3:h:fortinet:fortiadc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiADC},
	"FortiADCManager":                 {cpe: "cpe:2.3:h:fortinet:fortiadcmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiADCManager},
	"FortiAIOps":                      {cpe: "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAIOps},
	"FortiAP":                         {cpe: "cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAP},
	"FortiAP-C":                       {cpe: "cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPC},
	"FortiAP-S":                       {cpe: "cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPS},
	"FortiAP-U":                       {cpe: "cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPU},
	"FortiAP-W2":                      {cpe: "cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPW2},
	"FortiAnalyzer":                   {cpe: "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzer},
	"FortiAnalyzer Cloud":             {cpe: "cpe:2.3:a:fortinet:fortianalyzercloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerCloud},
	"FortiAnalyzer-BigData":           {cpe: "cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData},
	"FortiAuthenticator":              {cpe: "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator},
	"FortiAuthenticator OutlookAgent": {cpe: "cpe:2.3:a:fortinet:fortiauthenticatoroutlookagent:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator, twoComponentVersions: true},
	"FortiBalancer":                   {cpe: "cpe:2.3:h:fortinet:fortibalancer:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiBalancer},
	"FortiCASB":                       {cpe: "cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCASB},
	"FortiCache":                      {cpe: "cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCache},
	"FortiCamera":                     {cpe: "cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCamera},
	"FortiClient Lite":                {cpe: "cpe:2.3:a:fortinet:forticlientlite:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientLite},
	// The FortiClient platform variants (Windows/Mac/Linux/iOS/Android) each
	// take the CPE Fortinet gives the platform, and share one range type, as
	// do the other platform or deployment variants below (FortiToken Mobile,
	// FortiSOAR PaaS/on-premise).
	"FortiClientAndroid":                   {cpe: "cpe:2.3:a:fortinet:forticlientandroid:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientEMS":                       {cpe: "cpe:2.3:a:fortinet:forticlientems:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServer},
	"FortiClientEMS Cloud":                 {cpe: "cpe:2.3:a:fortinet:forticlientemscloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServerCloud},
	"FortiClientLinux":                     {cpe: "cpe:2.3:a:fortinet:forticlientlinux:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientMac":                       {cpe: "cpe:2.3:a:fortinet:forticlientmac:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientSSLVPN":                    {cpe: "cpe:2.3:a:fortinet:forticlientsslvpn:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientSSLVPN},
	"FortiClientWindows":                   {cpe: "cpe:2.3:a:fortinet:forticlientwindows:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientiOS":                       {cpe: "cpe:2.3:a:fortinet:forticlientios:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiCloud":                           {cpe: "cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCloud},
	"FortiConverter":                       {cpe: "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiConverter},
	"FortiDB":                              {cpe: "cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDB},
	"FortiDDoS":                            {cpe: "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoS},
	"FortiDDoS-CM":                         {cpe: "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSCM},
	"FortiDDoS-F":                          {cpe: "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSF},
	"FortiDLP":                             {cpe: "cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDLP},
	"FortiDeceptor":                        {cpe: "cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDeceptor},
	"FortiEDR":                             {cpe: "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR CollectorWindows":            {cpe: "cpe:2.3:a:fortinet:fortiedrcollectorwindows:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiedrmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDRManager},
	"FortiExplorer":                        {cpe: "cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiExplorer},
	"FortiExtender":                        {cpe: "cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiExtender},
	"FortiFone":                            {cpe: "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiFone},
	"FortiGate Cloud":                      {cpe: "cpe:2.3:a:fortinet:fortigatecloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiGateCloud},
	"FortiGuest":                           {cpe: "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiGuest},
	"FortiIsolator":                        {cpe: "cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiIsolator},
	"FortiMail":                            {cpe: "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiMail},
	"FortiManager":                         {cpe: "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiManager},
	"FortiManager Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortimanagercloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiManagerCloud},
	"FortiNAC":                             {cpe: "cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNAC},
	"FortiNAC-F":                           {cpe: "cpe:2.3:a:fortinet:fortinac-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNACF},
	"FortiNDR":                             {cpe: "cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNDR},
	"FortiOS":                              {cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOS},
	"FortiOS-6K7K":                         {cpe: "cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOS6k7k},
	"FortiPAM":                             {cpe: "cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPAM},
	"FortiPortal":                          {cpe: "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPortal},
	"FortiPresence":                        {cpe: "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPresence},
	"FortiProxy":                           {cpe: "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiProxy},
	"FortiRecorder":                        {cpe: "cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiRecorder},
	"FortiSASE":                            {cpe: "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSASE},
	"FortiSDNConnector":                    {cpe: "cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSDNConnector},
	"FortiSIEM":                            {cpe: "cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEM},
	"FortiSIEMWindowsAgent":                {cpe: "cpe:2.3:a:fortinet:fortisiemwindowsagent:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEMWindowsAgent},
	"FortiSOAR":                            {cpe: "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR Agent Communication Bridge": {cpe: "cpe:2.3:a:fortinet:fortisoaragentcommunicationbridge:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOARAgentCommunicationBridge},
	"FortiSOAR PaaS":                       {cpe: "cpe:2.3:a:fortinet:fortisoarpaas:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR on-premise":                 {cpe: "cpe:2.3:a:fortinet:fortisoaron-premise:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSRA":                             {cpe: "cpe:2.3:a:fortinet:fortisra:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSRA},
	"FortiSandbox":                         {cpe: "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandbox},
	"FortiSandbox Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortisandboxcloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxCloud},
	"FortiSandbox PaaS":                    {cpe: "cpe:2.3:a:fortinet:fortisandboxpaas:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxPaaS},
	"FortiSwitch":                          {cpe: "cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitch},
	"FortiSwitch-EFX":                      {cpe: "cpe:2.3:a:fortinet:fortiswitch-efx:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchEFX},
	"FortiSwitchAXFixed":                   {cpe: "cpe:2.3:a:fortinet:fortiswitchaxfixed:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchAXFixed},
	"FortiSwitchManager":                   {cpe: "cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchManager},
	"FortiTester":                          {cpe: "cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTester},
	"FortiTokenAndroid":                    {cpe: "cpe:2.3:a:fortinet:fortitokenandroid:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenIOS":                        {cpe: "cpe:2.3:a:fortinet:fortitokenios:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenMobileWP":                   {cpe: "cpe:2.3:a:fortinet:fortitokenmobilewp:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiVoice":                           {cpe: "cpe:2.3:a:fortinet:fortivoice:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiVoice},
	"FortiVoiceUCDesktop":                  {cpe: "cpe:2.3:a:fortinet:fortivoiceucdesktop:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop},
	"FortiWAN":                             {cpe: "cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWAN},
	"FortiWAN-Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiwan-manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWANManager},
	"FortiWLC":                             {cpe: "cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWLC},
	"FortiWLC-SD":                          {cpe: "cpe:2.3:a:fortinet:fortiwlc-sd:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWLCSD},
	"FortiWLM":                             {cpe: "cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWLM},
	"FortiWeb":                             {cpe: "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWeb},
	"FortiWebManager":                      {cpe: "cpe:2.3:a:fortinet:fortiwebmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWebManager},
	"IPS Engine":                           {cpe: "cpe:2.3:a:fortinet:ipsengine:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOSIPSEngine, twoComponentVersions: true},
	"Meru AP":                              {cpe: "cpe:2.3:h:fortinet:meruap:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetMeru},
}
