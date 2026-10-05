// Maps a Fortinet product name (as it appears in CSAF product nodes and CVRF
// "Product Name" branches) to the CPE 2.3 formatted strings (wildcard
// version) a host running it may be recorded under, and to its per-product
// cpecriterion range type. A name missing here makes the CSAF/CVRF extractor
// hard-error on the affected product rather than silently drop it, so add new
// Fortinet products here.
//
// A product carries two kinds of CPE, and the extractors match a host
// recorded under any of them. The first is the one Fortinet itself assigns,
// as CNA, in its CVE records (containers.cna.affected[].cpes on cve.org). The
// rest are the ones the CNA CPE would otherwise replace: the CPE this table
// published before, which follows NVD's enrichment where NVD has the
// product, so a host recorded the way NVD names the product keeps matching.
//
// Fortinet names each product apart (FortiClientWindows / FortiClientMac,
// FortiSOAR PaaS / on-premise) where NVD folds them into one product told
// apart by target_sw or not at all. On that side a platform variant takes
// NVD's product with NVD's target_sw for the platform (FortiClientMac both
// "macos" and the "mac_os_x" NVD gave its older releases), and a deployment
// NVD does not tell apart takes NVD's one product (FortiSOAR PaaS and
// on-premise both "fortisoar"). FortiAuthenticator OutlookAgent takes the
// product NVD gives the agent rather than FortiAuthenticator's.
//
// As of 2026-10, Fortinet's CPEs follow one rule — vendor "fortinet", product
// the product name lowercased with its spaces removed ("FortiSOAR
// on-premise" -> "fortisoaron-premise"), target_sw never set — and give each
// product one part across every record (FortiOS, FortiAnalyzer,
// FortiManager, FortiDDoS, FortiDDoS-F and FortiPAM "o"; FortiADC and
// FortiADCManager "h"; the rest "a"). The one exception to the naming is
// "FortiPAM Chrome Extension", which CVE-2026-84388 names
// "fortipam_chrome_extension", spaces turned into underscores: take a
// product's slug from its records whenever they give one, and derive it only
// when none does.
//
// For a product none of Fortinet's CVE records give a CPE yet, the CNA CPE's
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

// productInfo is a product's CPEs and its per-product range type. cpes holds
// the CNA CPE first, then each other CPE a host running the product may be
// recorded under (see the file comment), none repeated. Each product carries
// its own range type so a product whose version scheme later diverges gets its
// own comparator without affecting any other (see cpecriterion/range).
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
	cpes                 []string
	rangeType            ccRangeTypes.RangeType
	twoComponentVersions bool
}

var nameToProduct = map[string]productInfo{
	"AV Engine":                       {cpes: []string{"cpe:2.3:a:fortinet:avengine:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetAntivirusEngine, twoComponentVersions: true},
	"AscenLink":                       {cpes: []string{"cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetAscenLink},
	"Connect":                         {cpes: []string{"cpe:2.3:a:fortinet:connect:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetConnect},
	"FSSO":                            {cpes: []string{"cpe:2.3:a:fortinet:fsso:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortinet_single_sign-on:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFSSO},
	"FSSO CA":                         {cpes: []string{"cpe:2.3:a:fortinet:fssoca:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fsso_ca:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFSSOCA},
	"FortiADC":                        {cpes: []string{"cpe:2.3:h:fortinet:fortiadc:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiADC},
	"FortiADCManager":                 {cpes: []string{"cpe:2.3:h:fortinet:fortiadcmanager:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiADCManager},
	"FortiAIOps":                      {cpes: []string{"cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAIOps},
	"FortiAP":                         {cpes: []string{"cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAP},
	"FortiAP-C":                       {cpes: []string{"cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPC},
	"FortiAP-S":                       {cpes: []string{"cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPS},
	"FortiAP-U":                       {cpes: []string{"cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPU},
	"FortiAP-W2":                      {cpes: []string{"cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPW2},
	"FortiAnalyzer":                   {cpes: []string{"cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzer},
	"FortiAnalyzer Cloud":             {cpes: []string{"cpe:2.3:a:fortinet:fortianalyzercloud:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerCloud},
	"FortiAnalyzer-BigData":           {cpes: []string{"cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData},
	"FortiAuthenticator":              {cpes: []string{"cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator},
	"FortiAuthenticator OutlookAgent": {cpes: []string{"cpe:2.3:a:fortinet:fortiauthenticatoroutlookagent:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiauthenticator_agent_for_microsoft_outlook_web_access:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator, twoComponentVersions: true},
	"FortiBalancer":                   {cpes: []string{"cpe:2.3:h:fortinet:fortibalancer:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortibalancer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiBalancer},
	"FortiCASB":                       {cpes: []string{"cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCASB},
	"FortiCache":                      {cpes: []string{"cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCache},
	"FortiCamera":                     {cpes: []string{"cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCamera},
	"FortiClient Lite":                {cpes: []string{"cpe:2.3:a:fortinet:forticlientlite:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient_lite:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientLite},
	// The FortiClient platform variants (Windows/Mac/Linux/iOS/Android) each
	// take the CPE Fortinet gives the platform and NVD's for it, and share one
	// range type, as do the other platform or deployment variants below
	// (FortiToken Mobile, FortiSOAR PaaS/on-premise).
	"FortiClientAndroid":                   {cpes: []string{"cpe:2.3:a:fortinet:forticlientandroid:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:android:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientEMS":                       {cpes: []string{"cpe:2.3:a:fortinet:forticlientems:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServer},
	"FortiClientEMS Cloud":                 {cpes: []string{"cpe:2.3:a:fortinet:forticlientemscloud:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient_enterprise_management_server_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServerCloud},
	"FortiClientLinux":                     {cpes: []string{"cpe:2.3:a:fortinet:forticlientlinux:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:linux:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientMac":                       {cpes: []string{"cpe:2.3:a:fortinet:forticlientmac:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientSSLVPN":                    {cpes: []string{"cpe:2.3:a:fortinet:forticlientsslvpn:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientSSLVPN},
	"FortiClientWindows":                   {cpes: []string{"cpe:2.3:a:fortinet:forticlientwindows:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientiOS":                       {cpes: []string{"cpe:2.3:a:fortinet:forticlientios:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:iphone_os:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiCloud":                           {cpes: []string{"cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCloud},
	"FortiConverter":                       {cpes: []string{"cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiConverter},
	"FortiDB":                              {cpes: []string{"cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDB},
	"FortiDDoS":                            {cpes: []string{"cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoS},
	"FortiDDoS-CM":                         {cpes: []string{"cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSCM},
	"FortiDDoS-F":                          {cpes: []string{"cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSF},
	"FortiDLP":                             {cpes: []string{"cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDLP},
	"FortiDeceptor":                        {cpes: []string{"cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDeceptor},
	"FortiEDR":                             {cpes: []string{"cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR CollectorWindows":            {cpes: []string{"cpe:2.3:a:fortinet:fortiedrcollectorwindows:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR Manager":                     {cpes: []string{"cpe:2.3:a:fortinet:fortiedrmanager:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiedr_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDRManager},
	"FortiExplorer":                        {cpes: []string{"cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiExplorer},
	"FortiExtender":                        {cpes: []string{"cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiExtender},
	"FortiFone":                            {cpes: []string{"cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiFone},
	"FortiGate Cloud":                      {cpes: []string{"cpe:2.3:a:fortinet:fortigatecloud:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortigate_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiGateCloud},
	"FortiGuest":                           {cpes: []string{"cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiGuest},
	"FortiIsolator":                        {cpes: []string{"cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiIsolator},
	"FortiMail":                            {cpes: []string{"cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiMail},
	"FortiManager":                         {cpes: []string{"cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiManager},
	"FortiManager Cloud":                   {cpes: []string{"cpe:2.3:a:fortinet:fortimanagercloud:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiManagerCloud},
	"FortiNAC":                             {cpes: []string{"cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNAC},
	"FortiNAC-F":                           {cpes: []string{"cpe:2.3:a:fortinet:fortinac-f:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortinac-f:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNACF},
	"FortiNDR":                             {cpes: []string{"cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNDR},
	"FortiOS":                              {cpes: []string{"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOS},
	"FortiOS-6K7K":                         {cpes: []string{"cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOS6k7k},
	"FortiPAM":                             {cpes: []string{"cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPAM},
	"FortiPortal":                          {cpes: []string{"cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPortal},
	"FortiPresence":                        {cpes: []string{"cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPresence},
	"FortiProxy":                           {cpes: []string{"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiProxy},
	"FortiRecorder":                        {cpes: []string{"cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiRecorder},
	"FortiSASE":                            {cpes: []string{"cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSASE},
	"FortiSDNConnector":                    {cpes: []string{"cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSDNConnector},
	"FortiSIEM":                            {cpes: []string{"cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEM},
	"FortiSIEMWindowsAgent":                {cpes: []string{"cpe:2.3:a:fortinet:fortisiemwindowsagent:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisiem_windows_agent:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEMWindowsAgent},
	"FortiSOAR":                            {cpes: []string{"cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR Agent Communication Bridge": {cpes: []string{"cpe:2.3:a:fortinet:fortisoaragentcommunicationbridge:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisoar_agent_communication_bridge:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOARAgentCommunicationBridge},
	"FortiSOAR PaaS":                       {cpes: []string{"cpe:2.3:a:fortinet:fortisoarpaas:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR on-premise":                 {cpes: []string{"cpe:2.3:a:fortinet:fortisoaron-premise:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSRA":                             {cpes: []string{"cpe:2.3:a:fortinet:fortisra:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSRA},
	"FortiSandbox":                         {cpes: []string{"cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandbox},
	"FortiSandbox Cloud":                   {cpes: []string{"cpe:2.3:a:fortinet:fortisandboxcloud:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxCloud},
	"FortiSandbox PaaS":                    {cpes: []string{"cpe:2.3:a:fortinet:fortisandboxpaas:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisandbox_paas:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxPaaS},
	"FortiSwitch":                          {cpes: []string{"cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitch},
	"FortiSwitch-EFX":                      {cpes: []string{"cpe:2.3:a:fortinet:fortiswitch-efx:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiswitch-efx:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchEFX},
	"FortiSwitchAXFixed":                   {cpes: []string{"cpe:2.3:a:fortinet:fortiswitchaxfixed:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchAXFixed},
	"FortiSwitchManager":                   {cpes: []string{"cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchManager},
	"FortiTester":                          {cpes: []string{"cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTester},
	"FortiTokenAndroid":                    {cpes: []string{"cpe:2.3:a:fortinet:fortitokenandroid:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:android:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenIOS":                        {cpes: []string{"cpe:2.3:a:fortinet:fortitokenios:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:iphone_os:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenMobileWP":                   {cpes: []string{"cpe:2.3:a:fortinet:fortitokenmobilewp:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiVoice":                           {cpes: []string{"cpe:2.3:a:fortinet:fortivoice:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiVoice},
	"FortiVoiceUCDesktop":                  {cpes: []string{"cpe:2.3:a:fortinet:fortivoiceucdesktop:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications_desktop:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop},
	"FortiWAN":                             {cpes: []string{"cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWAN},
	"FortiWAN-Manager":                     {cpes: []string{"cpe:2.3:a:fortinet:fortiwan-manager:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWANManager},
	"FortiWLC":                             {cpes: []string{"cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLC},
	"FortiWLC-SD":                          {cpes: []string{"cpe:2.3:a:fortinet:fortiwlc-sd:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiwlc-sd:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLCSD},
	"FortiWLM":                             {cpes: []string{"cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLM},
	"FortiWeb":                             {cpes: []string{"cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWeb},
	"FortiWebManager":                      {cpes: []string{"cpe:2.3:a:fortinet:fortiwebmanager:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWebManager},
	"IPS Engine":                           {cpes: []string{"cpe:2.3:a:fortinet:ipsengine:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortios_ips_engine:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOSIPSEngine, twoComponentVersions: true},
	"Meru AP":                              {cpes: []string{"cpe:2.3:h:fortinet:meruap:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetMeru},
}
