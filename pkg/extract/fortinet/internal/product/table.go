// Derived from the curated CPEs in the legacy vuls-data-raw-fortinet
// (handmade) dataset, plus hand-added overrides for product names that
// dataset did not cover. Maps a Fortinet product name (as it appears in CSAF
// product nodes and CVRF "Product Name" branches) to its CPE 2.3 formatted
// string (wildcard version) and its per-product cpecriterion range type. A
// name missing here makes the CSAF/CVRF extractor hard-error on the affected
// product rather than silently drop it, so add new Fortinet products here.
package product

import (
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// productInfo is a product's CPE and its per-product range type. Each product
// carries its own range type so a product whose version scheme later diverges
// gets its own comparator without affecting any other (see cpecriterion/range).
type productInfo struct {
	cpe       string
	rangeType ccRangeTypes.RangeType
}

var nameToProduct = map[string]productInfo{
	"AV Engine":                            {cpe: "cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetAntivirusEngine},
	"AscenLink":                            {cpe: "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetAscenlink},
	"FortiADC":                             {cpe: "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiadc},
	"FortiADCManager":                      {cpe: "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiadcManager},
	"FortiAIOps":                           {cpe: "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiaiops},
	"FortiAP":                              {cpe: "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiap},
	"FortiAP-C":                            {cpe: "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiapC},
	"FortiAP-S":                            {cpe: "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiapS},
	"FortiAP-U":                            {cpe: "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiapU},
	"FortiAP-W2":                           {cpe: "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiapW2},
	"FortiAnalyzer":                        {cpe: "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortianalyzer},
	"FortiAnalyzer Cloud":                  {cpe: "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortianalyzerCloud},
	"FortiAnalyzer-BigData":                {cpe: "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortianalyzerBigdata},
	"FortiAuthenticator":                   {cpe: "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiauthenticator},
	"FortiAuthenticator OutlookAgent":      {cpe: "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiauthenticator},
	"FortiCache":                           {cpe: "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticache},
	"FortiCamera":                          {cpe: "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticamera},
	"FortiClientAndroid":                   {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlient},
	"FortiClientEMS":                       {cpe: "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlientEnterpriseManagementServer},
	"FortiClientEMS Cloud":                 {cpe: "cpe:2.3:a:fortinet:forticlient_enterprise_management_server_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlientEnterpriseManagementServerCloud},
	"FortiClientLinux":                     {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlient},
	"FortiClientMac":                       {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlient},
	"FortiClientWindows":                   {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlient},
	"FortiClientiOS":                       {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticlient},
	"FortiConverter":                       {cpe: "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetForticonverter},
	"FortiDB":                              {cpe: "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortidb},
	"FortiDDoS":                            {cpe: "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiddos},
	"FortiDDoS-CM":                         {cpe: "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiddosCm},
	"FortiDDoS-F":                          {cpe: "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiddosF},
	"FortiDLP":                             {cpe: "cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortidlp},
	"FortiDeceptor":                        {cpe: "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortideceptor},
	"FortiEDR":                             {cpe: "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiedr},
	"FortiEDR CollectorWindows":            {cpe: "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiedr},
	"FortiEDR Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiedr_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiedrManager},
	"FortiExtender":                        {cpe: "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiextender},
	"FortiFone":                            {cpe: "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortifone},
	"FortiGuest":                           {cpe: "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiguest},
	"FortiIsolator":                        {cpe: "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiisolator},
	"FortiMail":                            {cpe: "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortimail},
	"FortiManager":                         {cpe: "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortimanager},
	"FortiManager Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortimanagerCloud},
	"FortiNAC":                             {cpe: "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortinac},
	"FortiNAC-F":                           {cpe: "cpe:2.3:o:fortinet:fortinac-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortinacF},
	"FortiNDR":                             {cpe: "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortindr},
	"FortiOS":                              {cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortios},
	"FortiOS-6K7K":                         {cpe: "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortios6k7k},
	"FortiPAM":                             {cpe: "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortipam},
	"FortiPortal":                          {cpe: "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiportal},
	"FortiPresence":                        {cpe: "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortipresence},
	"FortiProxy":                           {cpe: "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiproxy},
	"FortiRecorder":                        {cpe: "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortirecorder},
	"FortiSASE":                            {cpe: "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisase},
	"FortiSIEM":                            {cpe: "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisiem},
	"FortiSOAR Agent Communication Bridge": {cpe: "cpe:2.3:a:fortinet:fortisoar_agent_communication_bridge:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisoarAgentCommunicationBridge},
	"FortiSOAR PaaS":                       {cpe: "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisoar},
	"FortiSOAR on-premise":                 {cpe: "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisoar},
	"FortiSRA":                             {cpe: "cpe:2.3:a:fortinet:fortisra:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisra},
	"FortiSandbox":                         {cpe: "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisandbox},
	"FortiSandbox Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisandboxCloud},
	"FortiSandbox PaaS":                    {cpe: "cpe:2.3:a:fortinet:fortisandbox_paas:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortisandboxPaas},
	"FortiSwitch":                          {cpe: "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiswitch},
	"FortiSwitchAXFixed":                   {cpe: "cpe:2.3:a:fortinet:fortiswitchaxfixed:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiswitchaxfixed},
	"FortiSwitchManager":                   {cpe: "cpe:2.3:o:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiswitchmanager},
	"FortiTester":                          {cpe: "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortitester},
	"FortiTokenAndroid":                    {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortitokenMobile},
	"FortiTokenIOS":                        {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortitokenMobile},
	"FortiTokenMobileWP":                   {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortitokenMobile},
	"FortiVoice":                           {cpe: "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortivoice},
	"FortiVoiceUCDesktop":                  {cpe: "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications_desktop:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortivoiceCloudUnifiedCommunicationsDesktop},
	"FortiWAN":                             {cpe: "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiwan},
	"FortiWAN-Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiwanManager},
	"FortiWLC":                             {cpe: "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiwlc},
	"FortiWLM":                             {cpe: "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiwlm},
	"FortiWeb":                             {cpe: "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiweb},
	"FortiWebManager":                      {cpe: "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiwebManager},
	"IPS Engine":                           {cpe: "cpe:2.3:a:fortinet:fortios_ips_engine:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiosIpsEngine},
	"Meru AP":                              {cpe: "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetMeru},
}
