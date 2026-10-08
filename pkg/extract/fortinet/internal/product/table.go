// Maps a Fortinet product name (as it appears in CSAF product nodes and CVRF
// "Product Name" branches) to the CPE 2.3 formatted strings (wildcard
// version) a host running it may be recorded under, and to its per-product
// cpecriterion range type. A name missing here makes the CSAF/CVRF extractor
// hard-error on the affected product rather than silently drop it, so add new
// Fortinet products here.
//
// A product carries two kinds of CPE, and the extractors match a host
// recorded under any of them. cna is the one Fortinet itself assigns, as CNA,
// in its CVE records (containers.cna.affected[].cpes on cve.org). nvd is the
// one the CNA CPE would otherwise replace: the CPE this table published
// before, which follows NVD's enrichment where NVD has the product, so a host
// recorded the way NVD names the product keeps matching. nvd is left out
// where it is the CNA CPE.
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

// productInfo is a product's CPEs and its per-product range type. cna holds
// the CPEs Fortinet assigns the product as CNA — one today for every product,
// but a list, since the CNA derives each record's CPE from the product name as
// typed into that record and nothing keeps two records from spelling it
// apart — or, for a product none of its records give a CPE yet, the one its
// rule derives. nvd holds the CPEs this table published before, NVD's where
// NVD has the product (see the file comment), so a host recorded the way NVD
// names it keeps matching. No CPE appears twice across the two. Each product
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
	cna                  []string
	nvd                  []string
	rangeType            ccRangeTypes.RangeType
	twoComponentVersions bool
}

var nameToProduct = map[string]productInfo{
	"AV Engine":                       {cna: []string{"cpe:2.3:a:fortinet:avengine:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetAntivirusEngine, twoComponentVersions: true},
	"AscenLink":                       {cna: []string{"cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetAscenLink},
	"Connect":                         {cna: []string{"cpe:2.3:a:fortinet:connect:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetConnect},
	"FSSO":                            {cna: []string{"cpe:2.3:a:fortinet:fsso:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortinet_single_sign-on:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFSSO},
	"FSSO CA":                         {cna: []string{"cpe:2.3:a:fortinet:fssoca:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fsso_ca:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFSSOCA},
	"FortiADC":                        {cna: []string{"cpe:2.3:h:fortinet:fortiadc:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiADC},
	"FortiADCManager":                 {cna: []string{"cpe:2.3:h:fortinet:fortiadcmanager:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiADCManager},
	"FortiAIOps":                      {cna: []string{"cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAIOps},
	"FortiAP":                         {cna: []string{"cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAP},
	"FortiAP-C":                       {cna: []string{"cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPC},
	"FortiAP-S":                       {cna: []string{"cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPS},
	"FortiAP-U":                       {cna: []string{"cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPU},
	"FortiAP-W2":                      {cna: []string{"cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAPW2},
	"FortiAnalyzer":                   {cna: []string{"cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzer},
	"FortiAnalyzer Cloud":             {cna: []string{"cpe:2.3:a:fortinet:fortianalyzercloud:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerCloud},
	"FortiAnalyzer-BigData":           {cna: []string{"cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData},
	"FortiAuthenticator":              {cna: []string{"cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator},
	"FortiAuthenticator OutlookAgent": {cna: []string{"cpe:2.3:a:fortinet:fortiauthenticatoroutlookagent:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiauthenticator_agent_for_microsoft_outlook_web_access:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator, twoComponentVersions: true},
	"FortiBalancer":                   {cna: []string{"cpe:2.3:h:fortinet:fortibalancer:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortibalancer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiBalancer},
	"FortiCASB":                       {cna: []string{"cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCASB},
	"FortiCache":                      {cna: []string{"cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCache},
	"FortiCamera":                     {cna: []string{"cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCamera},
	"FortiClient Lite":                {cna: []string{"cpe:2.3:a:fortinet:forticlientlite:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient_lite:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientLite},
	// The FortiClient platform variants (Windows/Mac/Linux/iOS/Android) each
	// take the CPE Fortinet gives the platform and NVD's for it, and share one
	// range type, as do the other platform or deployment variants below
	// (FortiToken Mobile, FortiSOAR PaaS/on-premise).
	"FortiClientAndroid":                   {cna: []string{"cpe:2.3:a:fortinet:forticlientandroid:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:android:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientEMS":                       {cna: []string{"cpe:2.3:a:fortinet:forticlientems:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServer},
	"FortiClientEMS Cloud":                 {cna: []string{"cpe:2.3:a:fortinet:forticlientemscloud:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient_enterprise_management_server_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServerCloud},
	"FortiClientLinux":                     {cna: []string{"cpe:2.3:a:fortinet:forticlientlinux:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:linux:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientMac":                       {cna: []string{"cpe:2.3:a:fortinet:forticlientmac:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientSSLVPN":                    {cna: []string{"cpe:2.3:a:fortinet:forticlientsslvpn:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClientSSLVPN},
	"FortiClientWindows":                   {cna: []string{"cpe:2.3:a:fortinet:forticlientwindows:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientiOS":                       {cna: []string{"cpe:2.3:a:fortinet:forticlientios:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:iphone_os:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiCloud":                           {cna: []string{"cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiCloud},
	"FortiConverter":                       {cna: []string{"cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiConverter},
	"FortiDB":                              {cna: []string{"cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDB},
	"FortiDDoS":                            {cna: []string{"cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoS},
	"FortiDDoS-CM":                         {cna: []string{"cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSCM},
	"FortiDDoS-F":                          {cna: []string{"cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSF},
	"FortiDLP":                             {cna: []string{"cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDLP},
	"FortiDeceptor":                        {cna: []string{"cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiDeceptor},
	"FortiEDR":                             {cna: []string{"cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR CollectorWindows":            {cna: []string{"cpe:2.3:a:fortinet:fortiedrcollectorwindows:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR Manager":                     {cna: []string{"cpe:2.3:a:fortinet:fortiedrmanager:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiedr_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiEDRManager},
	"FortiExplorer":                        {cna: []string{"cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiExplorer},
	"FortiExtender":                        {cna: []string{"cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiExtender},
	"FortiFone":                            {cna: []string{"cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiFone},
	"FortiGate Cloud":                      {cna: []string{"cpe:2.3:a:fortinet:fortigatecloud:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortigate_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiGateCloud},
	"FortiGuest":                           {cna: []string{"cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiGuest},
	"FortiIsolator":                        {cna: []string{"cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiIsolator},
	"FortiMail":                            {cna: []string{"cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiMail},
	"FortiManager":                         {cna: []string{"cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiManager},
	"FortiManager Cloud":                   {cna: []string{"cpe:2.3:a:fortinet:fortimanagercloud:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiManagerCloud},
	"FortiNAC":                             {cna: []string{"cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNAC},
	"FortiNAC-F":                           {cna: []string{"cpe:2.3:a:fortinet:fortinac-f:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortinac-f:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNACF},
	"FortiNDR":                             {cna: []string{"cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiNDR},
	"FortiOS":                              {cna: []string{"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOS},
	"FortiOS-6K7K":                         {cna: []string{"cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOS6k7k},
	"FortiPAM":                             {cna: []string{"cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPAM},
	"FortiPortal":                          {cna: []string{"cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPortal},
	"FortiPresence":                        {cna: []string{"cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiPresence},
	"FortiProxy":                           {cna: []string{"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiProxy},
	"FortiRecorder":                        {cna: []string{"cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiRecorder},
	"FortiSASE":                            {cna: []string{"cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSASE},
	"FortiSDNConnector":                    {cna: []string{"cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSDNConnector},
	"FortiSIEM":                            {cna: []string{"cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEM},
	"FortiSIEM Cloud":                      {cna: []string{"cpe:2.3:a:fortinet:fortisiemcloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEMCloud},
	"FortiSIEMWindowsAgent":                {cna: []string{"cpe:2.3:a:fortinet:fortisiemwindowsagent:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisiem_windows_agent:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEMWindowsAgent},
	"FortiSOAR":                            {cna: []string{"cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR Agent Communication Bridge": {cna: []string{"cpe:2.3:a:fortinet:fortisoaragentcommunicationbridge:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisoar_agent_communication_bridge:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOARAgentCommunicationBridge},
	"FortiSOAR PaaS":                       {cna: []string{"cpe:2.3:a:fortinet:fortisoarpaas:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR on-premise":                 {cna: []string{"cpe:2.3:a:fortinet:fortisoaron-premise:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSRA":                             {cna: []string{"cpe:2.3:a:fortinet:fortisra:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSRA},
	"FortiSandbox":                         {cna: []string{"cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandbox},
	"FortiSandbox Cloud":                   {cna: []string{"cpe:2.3:a:fortinet:fortisandboxcloud:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxCloud},
	"FortiSandbox PaaS":                    {cna: []string{"cpe:2.3:a:fortinet:fortisandboxpaas:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortisandbox_paas:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxPaaS},
	"FortiSwitch":                          {cna: []string{"cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitch},
	"FortiSwitch-EFX":                      {cna: []string{"cpe:2.3:a:fortinet:fortiswitch-efx:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiswitch-efx:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchEFX},
	"FortiSwitchAXFixed":                   {cna: []string{"cpe:2.3:a:fortinet:fortiswitchaxfixed:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchAXFixed},
	"FortiSwitchManager":                   {cna: []string{"cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchManager},
	"FortiTester":                          {cna: []string{"cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTester},
	"FortiTokenAndroid":                    {cna: []string{"cpe:2.3:a:fortinet:fortitokenandroid:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:android:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenIOS":                        {cna: []string{"cpe:2.3:a:fortinet:fortitokenios:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:iphone_os:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenMobileWP":                   {cna: []string{"cpe:2.3:a:fortinet:fortitokenmobilewp:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:windows:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiVoice":                           {cna: []string{"cpe:2.3:a:fortinet:fortivoice:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortivoice:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiVoice},
	"FortiVoiceUCDesktop":                  {cna: []string{"cpe:2.3:a:fortinet:fortivoiceucdesktop:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications_desktop:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop},
	"FortiWAN":                             {cna: []string{"cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWAN},
	"FortiWAN-Manager":                     {cna: []string{"cpe:2.3:a:fortinet:fortiwan-manager:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWANManager},
	"FortiWLC":                             {cna: []string{"cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLC},
	"FortiWLC-SD":                          {cna: []string{"cpe:2.3:a:fortinet:fortiwlc-sd:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiwlc-sd:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLCSD},
	"FortiWLM":                             {cna: []string{"cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWLM},
	"FortiWeb":                             {cna: []string{"cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWeb},
	"FortiWebManager":                      {cna: []string{"cpe:2.3:a:fortinet:fortiwebmanager:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiWebManager},
	"IPS Engine":                           {cna: []string{"cpe:2.3:a:fortinet:ipsengine:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:fortios_ips_engine:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetFortiOSIPSEngine, twoComponentVersions: true},
	"Meru AP":                              {cna: []string{"cpe:2.3:h:fortinet:meruap:*:*:*:*:*:*:*:*"}, nvd: []string{"cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*"}, rangeType: ccRangeTypes.RangeTypeFortinetMeru},
}
