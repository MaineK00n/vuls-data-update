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
	"AscenLink":                            {cpe: "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetAscenLink},
	"FortiADC":                             {cpe: "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiADC},
	"FortiADCManager":                      {cpe: "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiADCManager},
	"FortiAIOps":                           {cpe: "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAIOps},
	"FortiAP":                              {cpe: "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAP},
	"FortiAP-C":                            {cpe: "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPC},
	"FortiAP-S":                            {cpe: "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPS},
	"FortiAP-U":                            {cpe: "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPU},
	"FortiAP-W2":                           {cpe: "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAPW2},
	"FortiAnalyzer":                        {cpe: "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzer},
	"FortiAnalyzer Cloud":                  {cpe: "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerCloud},
	"FortiAnalyzer-BigData":                {cpe: "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData},
	"FortiAuthenticator":                   {cpe: "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator},
	"FortiAuthenticator OutlookAgent":      {cpe: "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiAuthenticator},
	"FortiCache":                           {cpe: "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCache},
	"FortiCamera":                          {cpe: "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiCamera},
	"FortiClientAndroid":                   {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientEMS":                       {cpe: "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServer},
	"FortiClientEMS Cloud":                 {cpe: "cpe:2.3:a:fortinet:forticlient_enterprise_management_server_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClientEnterpriseManagementServerCloud},
	"FortiClientLinux":                     {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientMac":                       {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientWindows":                   {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiClientiOS":                       {cpe: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiClient},
	"FortiConverter":                       {cpe: "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiConverter},
	"FortiDB":                              {cpe: "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDB},
	"FortiDDoS":                            {cpe: "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoS},
	"FortiDDoS-CM":                         {cpe: "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSCM},
	"FortiDDoS-F":                          {cpe: "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDDoSF},
	"FortiDLP":                             {cpe: "cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDLP},
	"FortiDeceptor":                        {cpe: "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiDeceptor},
	"FortiEDR":                             {cpe: "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR CollectorWindows":            {cpe: "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDR},
	"FortiEDR Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiedr_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiEDRManager},
	"FortiExtender":                        {cpe: "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiExtender},
	"FortiFone":                            {cpe: "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiFone},
	"FortiGuest":                           {cpe: "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiGuest},
	"FortiIsolator":                        {cpe: "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiIsolator},
	"FortiMail":                            {cpe: "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiMail},
	"FortiManager":                         {cpe: "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiManager},
	"FortiManager Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiManagerCloud},
	"FortiNAC":                             {cpe: "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNAC},
	"FortiNAC-F":                           {cpe: "cpe:2.3:o:fortinet:fortinac-f:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNACF},
	"FortiNDR":                             {cpe: "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiNDR},
	"FortiOS":                              {cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOS},
	"FortiOS-6K7K":                         {cpe: "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOS6k7k},
	"FortiPAM":                             {cpe: "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPAM},
	"FortiPortal":                          {cpe: "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPortal},
	"FortiPresence":                        {cpe: "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiPresence},
	"FortiProxy":                           {cpe: "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiProxy},
	"FortiRecorder":                        {cpe: "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiRecorder},
	"FortiSASE":                            {cpe: "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSASE},
	"FortiSIEM":                            {cpe: "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSIEM},
	"FortiSOAR Agent Communication Bridge": {cpe: "cpe:2.3:a:fortinet:fortisoar_agent_communication_bridge:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOARAgentCommunicationBridge},
	"FortiSOAR PaaS":                       {cpe: "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSOAR on-premise":                 {cpe: "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSOAR},
	"FortiSRA":                             {cpe: "cpe:2.3:a:fortinet:fortisra:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSRA},
	"FortiSandbox":                         {cpe: "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandbox},
	"FortiSandbox Cloud":                   {cpe: "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxCloud},
	"FortiSandbox PaaS":                    {cpe: "cpe:2.3:a:fortinet:fortisandbox_paas:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSandboxPaaS},
	"FortiSwitch":                          {cpe: "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitch},
	"FortiSwitchAXFixed":                   {cpe: "cpe:2.3:a:fortinet:fortiswitchaxfixed:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchAXFixed},
	"FortiSwitchManager":                   {cpe: "cpe:2.3:o:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiSwitchManager},
	"FortiTester":                          {cpe: "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTester},
	"FortiTokenAndroid":                    {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenIOS":                        {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiTokenMobileWP":                   {cpe: "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiTokenMobile},
	"FortiVoice":                           {cpe: "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiVoice},
	"FortiVoiceUCDesktop":                  {cpe: "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications_desktop:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiVoiceCloudUnifiedCommunicationsDesktop},
	"FortiWAN":                             {cpe: "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWAN},
	"FortiWAN-Manager":                     {cpe: "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWANManager},
	"FortiWLC":                             {cpe: "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWLC},
	"FortiWLM":                             {cpe: "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWLM},
	"FortiWeb":                             {cpe: "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWeb},
	"FortiWebManager":                      {cpe: "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiWebManager},
	"IPS Engine":                           {cpe: "cpe:2.3:a:fortinet:fortios_ips_engine:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetFortiOSIPSEngine},
	"Meru AP":                              {cpe: "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*", rangeType: ccRangeTypes.RangeTypeFortinetMeru},
}
