package bulletin

import (
	"strings"

	bulletin "github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/bulletin"
)

// bulletinArchiveAmendment groups every static correction that an MSRC
// Bulletin contributes to the extracted dataset under a single per-bulletin
// record. Each field captures one axis of the correction, but all of them
// share the same scoping rule: an entry in MS-X's amendment only affects
// rows / chain edges that MS-X itself authored.
//
// Why per-bulletin? Earlier iterations spread these corrections across seven
// top-level maps (bulletinArchiveKBNotApplicable, *ComponentNotApplicable,
// *CVECorrections, *CVEAdditions, *ComponentReattribution, *Supersedes,
// *SupersedesOverride) keyed variously by KB / (bulletin, component) /
// bulletin / etc. Reviewing "what does MS17-006 change?" required grepping
// each map. Cross-bulletin influence was also implicit — a KB-keyed NA
// entry contributed by MS-A would silently apply to any other bulletin's
// row that happened to share the KB. Per-bulletin grouping makes the
// authorship explicit (each entry lives under the bulletin whose markdown
// documents it) and bounds the influence to that bulletin's rows at
// runtime.
//
// Runtime semantics:
//   - CVEAdjustments: applied to each row whose row.BulletinID matches the
//     map key. Each adjustment optionally narrows by KB and/or component
//     and then drops / adds / remaps CVE tokens.
//   - RowSplits: applied to each OS-only row (AffectedComponent == "") whose
//     (BulletinID, ComponentKB) matches a split entry. Listed CVEs move
//     from the source row to a synthesized (OS + component) row.
//   - Supersedes: per-(this bulletin's) KB add/override edges that are
//     merged into the global kbSupersededBy graph once after all xlsx rows
//     are processed.
//   - IECumChain: per-(this bulletin's) IE Cumulative chain edges. The
//     bulletin's amendment carries oldKBID → []newKBIDs where each newKBID
//     was released by this bulletin and supersedes oldKBID. Iterated once
//     globally across all bulletins to augment kbSupersededBy.
type bulletinArchiveAmendment struct {
	CVEAdjustments []cveAdjustment
	RowSplits      []rowSplit
	Supersedes     map[string]supersedesAdjust
	IECumChain     map[string][]string
}

// cveAdjustment selects rows of the owning bulletin by (optional KB,
// optional component) and rewrites their CVE list.
//
// Selector semantics:
//   - KB == "" matches any row.ComponentKB; KB != "" requires equality.
//   - Component == "" matches any row; Component != "" requires
//     normalizeArchiveComponentKey(row) == Component.
//   - When both fields are non-empty the row must satisfy both.
//   - When both are empty the adjustment applies to every row of the
//     owning bulletin.
//
// Action semantics (applied in this order when multiple fields are set):
//  1. Remap: for each CVE in row.CVEs, if Remap[token] != "" replace it
//     with the mapped value; if Remap[token] == "" the token is dropped.
//  2. Drop: remove any token listed here from row.CVEs.
//  3. Add: union the listed CVEs into row.CVEs.
//
// At most one of the three fields is populated in practice; combining
// them is supported but discouraged because it makes the entry harder to
// read.
type cveAdjustment struct {
	KB        string
	Component string
	Drop      []string
	Add       []string
	Remap     map[string]string
}

// rowSplit synthesizes a per-component row alongside the OS-only xlsx
// row it splits off from. It is applied only to rows where:
//
//	row.BulletinID == owning bulletin
//	row.ComponentKB == KB
//	row.AffectedComponent == ""    (OS-only row)
//
// The synthesized row carries the listed Component as affected_component
// and only the listed CVEs; the source row's CVE list has those CVEs
// removed.
type rowSplit struct {
	KB        string
	Component string
	CVEs      []string
}

// supersedesAdjust amends the supersedes edges for a single KB.
// Add: superseded-by KBs to union into the global kbSupersededBy[KB] set.
// Override: superseded-by KBs that BulletinSearch.xlsx incorrectly
// attributes to this KB and should be removed from kbSupersededBy[KB].
type supersedesAdjust struct {
	Add      []string
	Override []string
}

// bulletinArchiveAmendments is the single source of truth for static
// per-bulletin corrections to the extracted dataset. Entries are added
// incrementally by the migration that consolidates the legacy top-level
// amendment maps; once that migration completes, the legacy maps are
// removed.
var bulletinArchiveAmendments = map[string]bulletinArchiveAmendment{
	"MS02-019": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2002-0153"}}}},
	"MS02-038": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2002-0644", "CVE-2002-0645"}}}},
	"MS06-007": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2006-0021"}}}},
	"MS06-015": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2004-2289", "CVE-2006-0012"}}}},
	"MS06-021": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2005-4089", "CVE-2006-1303", "CVE-2006-1626", "CVE-2006-1992", "CVE-2006-2218", "CVE-2006-2382", "CVE-2006-2383", "CVE-2006-2384", "CVE-2006-2385"}}}},
	"MS06-039": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2006-0007", "CVE-2006-0033"}}}},
	"MS07-002": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-0027", "CVE-2007-0028", "CVE-2007-0029", "CVE-2007-0030", "CVE-2007-0031"}}}},
	"MS07-039": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-0040", "CVE-2007-3028"}}}},
	// MS07-040 includes CVE-2006-7192 because the bulletin's V1.0 note
	// states the update "includes a defense-in-depth change to ASP.NET
	// ... mitigates the issue ... CVE-2006-7192". Mitigation rather
	// than full fix, but the KB is the only vehicle delivering the
	// protection.
	"MS07-040": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2006-7192", "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043"}}}},
	"MS07-045": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-0943", "CVE-2007-1891", "CVE-2007-1892", "CVE-2007-2216", "CVE-2007-3041"}}}},
	"MS07-069": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2007-3902", "CVE-2007-3903", "CVE-2007-5344", "CVE-2007-5347"}}}},
	"MS08-028": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2005-0944", "CVE-2007-6026"}}}},
	"MS08-029": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-1437", "CVE-2008-1438"}}}},
	"MS08-038": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-0951", "CVE-2008-1435"}}}},
	"MS08-058": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-2947", "CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476"}}}},
	"MS08-059": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2008-3466"}}}},
	"MS09-020": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2009-1122", "CVE-2009-1535", "CVE-2009-1676"}}}},
	"MS09-072": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3672", "CVE-2009-3673", "CVE-2009-3674"}}}},
	"MS11-050": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1246", "CVE-2011-1250", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258", "CVE-2011-1260", "CVE-2011-1261", "CVE-2011-1262", "CVE-2011-1346"}}}},
	// MS11-057 includes CVE-2011-1347 because the bulletin's update FAQ
	// states "this update addresses a Protected Mode bypass issue,
	// publicly disclosed". The CVE is not in the main vulnerability
	// table but the update explicitly addresses it.
	"MS11-057": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1257", "CVE-2011-1347", "CVE-2011-1960", "CVE-2011-1961", "CVE-2011-1962", "CVE-2011-1963", "CVE-2011-1964", "CVE-2011-2383"}}}},
	"MS11-091": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412"}}}},
	"MS11-096": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1986", "CVE-2011-1987", "CVE-2011-3403"}}}},
	"MS11-099": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-1992", "CVE-2011-2019", "CVE-2011-3389", "CVE-2011-3404"}}}},
	"MS11-100": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-3414", "CVE-2011-3415", "CVE-2011-3416", "CVE-2011-3417", "CVE-2012-0160", "CVE-2012-0161"}}}},
	"MS12-039": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858"}}}},
	"MS12-080": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2012-3214", "CVE-2012-3217", "CVE-2012-4791"}}}},
	"MS13-028": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2013-1303", "CVE-2013-1304", "CVE-2013-1338"}}}},
	"MS13-059": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2013-3184", "CVE-2013-3186", "CVE-2013-3187", "CVE-2013-3188", "CVE-2013-3189", "CVE-2013-3190", "CVE-2013-3191", "CVE-2013-3192", "CVE-2013-3193", "CVE-2013-3194", "CVE-2013-3199"}}}},
	"MS13-063": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2013-2556", "CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198"}}}},
	"MS13-072": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858"}}}},
	"MS13-076": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2013-1341", "CVE-2013-1342", "CVE-2013-1343", "CVE-2013-1344", "CVE-2013-3864", "CVE-2013-3865", "CVE-2013-3866"}}}},
	"MS14-075": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2014-6319", "CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336"}}}},
	"MS15-018": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-0032", "CVE-2015-0056", "CVE-2015-0072", "CVE-2015-0099", "CVE-2015-0100", "CVE-2015-1622", "CVE-2015-1623", "CVE-2015-1624", "CVE-2015-1625", "CVE-2015-1626", "CVE-2015-1627", "CVE-2015-1634"}}}},
	"MS15-032": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2014-6374", "CVE-2015-1652", "CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1661", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1666", "CVE-2015-1667", "CVE-2015-1668"}}}},
	"MS15-036": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-1640", "CVE-2015-1653"}}}},
	"MS15-048": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-1672", "CVE-2015-1673"}}}},
	"MS15-061": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-1719", "CVE-2015-1720", "CVE-2015-1721", "CVE-2015-1722", "CVE-2015-1723", "CVE-2015-1724", "CVE-2015-1725", "CVE-2015-1726", "CVE-2015-1727", "CVE-2015-1768", "CVE-2015-2360"}}}},
	"MS15-094": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-2483", "CVE-2015-2484", "CVE-2015-2485", "CVE-2015-2486", "CVE-2015-2487", "CVE-2015-2489", "CVE-2015-2490", "CVE-2015-2491", "CVE-2015-2492", "CVE-2015-2493", "CVE-2015-2494", "CVE-2015-2496", "CVE-2015-2498", "CVE-2015-2499", "CVE-2015-2500", "CVE-2015-2501", "CVE-2015-2541", "CVE-2015-2542"}}}},
	"MS15-099": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2522", "CVE-2015-2523", "CVE-2015-2545"}}}},
	"MS15-106": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-2482", "CVE-2015-6042", "CVE-2015-6044", "CVE-2015-6045", "CVE-2015-6046", "CVE-2015-6047", "CVE-2015-6048", "CVE-2015-6049", "CVE-2015-6050", "CVE-2015-6051", "CVE-2015-6052", "CVE-2015-6053", "CVE-2015-6055", "CVE-2015-6056", "CVE-2015-6059", "CVE-2015-6184"}}}},
	"MS15-110": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-2555", "CVE-2015-2556", "CVE-2015-2557", "CVE-2015-2558", "CVE-2015-6037", "CVE-2015-6039"}}}},
	"MS15-116": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-2503", "CVE-2015-6038", "CVE-2015-6091", "CVE-2015-6092", "CVE-2015-6093", "CVE-2015-6094", "CVE-2015-6123"}}}},
	"MS15-128": {
		RowSplits: []rowSplit{
			{KB: "3116869", Component: "Microsoft .NET Framework 3.5", CVEs: []string{"CVE-2015-6108"}},
		},
	},
	"MS16-002": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0003", "CVE-2016-0024"}}}},
	"MS16-004": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-6117", "CVE-2015-6177", "CVE-2016-0010", "CVE-2016-0011", "CVE-2016-0012", "CVE-2016-0035"}}}},
	"MS16-022": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967", "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971", "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975", "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979", "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983", "CVE-2016-0984", "CVE-2016-0985"}}}},
	"MS16-036": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-8652", "CVE-2015-8655", "CVE-2015-8658", "CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963", "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989", "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0993", "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-1001", "CVE-2016-1005", "CVE-2016-1010"}}}},
	"MS16-050": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013", "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017", "CVE-2016-1018", "CVE-2016-1019"}}}},
	"MS16-064": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099", "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103", "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107", "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108", "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112", "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116", "CVE-2016-4117"}}}},
	"MS16-077": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3213", "CVE-2016-3236", "CVE-2016-3299"}}}},
	"MS16-083": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4121", "CVE-2016-4122", "CVE-2016-4123", "CVE-2016-4124", "CVE-2016-4125", "CVE-2016-4126", "CVE-2016-4127", "CVE-2016-4128", "CVE-2016-4129", "CVE-2016-4130", "CVE-2016-4131", "CVE-2016-4132", "CVE-2016-4133", "CVE-2016-4134", "CVE-2016-4135", "CVE-2016-4136", "CVE-2016-4137", "CVE-2016-4138", "CVE-2016-4139", "CVE-2016-4140", "CVE-2016-4141", "CVE-2016-4142", "CVE-2016-4143", "CVE-2016-4144", "CVE-2016-4145", "CVE-2016-4146", "CVE-2016-4147", "CVE-2016-4148", "CVE-2016-4149", "CVE-2016-4150", "CVE-2016-4151", "CVE-2016-4152", "CVE-2016-4153", "CVE-2016-4154", "CVE-2016-4155", "CVE-2016-4156", "CVE-2016-4166", "CVE-2016-4171"}}}},
	"MS16-084": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3204", "CVE-2016-3240", "CVE-2016-3241", "CVE-2016-3242", "CVE-2016-3243", "CVE-2016-3245", "CVE-2016-3248", "CVE-2016-3259", "CVE-2016-3260", "CVE-2016-3261", "CVE-2016-3264", "CVE-2016-3273", "CVE-2016-3274", "CVE-2016-3277"}}}},
	"MS16-093": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4182", "CVE-2016-4185", "CVE-2016-4188", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249"}}}},
	"MS16-105": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3294", "CVE-2016-3295", "CVE-2016-3297", "CVE-2016-3325", "CVE-2016-3330", "CVE-2016-3350", "CVE-2016-3351", "CVE-2016-3370", "CVE-2016-3374", "CVE-2016-3377"}}}},
	// MS16-108 covers the Oracle Outside In Libraries Vulnerabilities
	// per Oracle Critical Patch Update Advisory - July 2016. The CVEs
	// are listed inline-grouped by severity (RCE / Info Disclosure /
	// DoS) in the bulletin body rather than in per-CVE section
	// headings, which is why the harvester sees them once each in
	// markdown.
	"MS16-108": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2015-6014", "CVE-2016-0138", "CVE-2016-3378", "CVE-2016-3379", "CVE-2016-3574", "CVE-2016-3575", "CVE-2016-3576", "CVE-2016-3577", "CVE-2016-3578", "CVE-2016-3579", "CVE-2016-3580", "CVE-2016-3581", "CVE-2016-3582", "CVE-2016-3583", "CVE-2016-3590", "CVE-2016-3591", "CVE-2016-3592", "CVE-2016-3593", "CVE-2016-3594", "CVE-2016-3595", "CVE-2016-3596"}}}},
	"MS16-117": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4271", "CVE-2016-4272", "CVE-2016-4274", "CVE-2016-4275", "CVE-2016-4276", "CVE-2016-4277", "CVE-2016-4278", "CVE-2016-4279", "CVE-2016-4280", "CVE-2016-4281", "CVE-2016-4282", "CVE-2016-4283", "CVE-2016-4284", "CVE-2016-4285", "CVE-2016-4287", "CVE-2016-6921", "CVE-2016-6922", "CVE-2016-6923", "CVE-2016-6924", "CVE-2016-6925", "CVE-2016-6926", "CVE-2016-6927", "CVE-2016-6929", "CVE-2016-6930", "CVE-2016-6931", "CVE-2016-6932"}}}},
	"MS16-123": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-3266", "CVE-2016-3341", "CVE-2016-3376", "CVE-2016-7185", "CVE-2016-7191", "CVE-2016-7211"}}}},
	"MS16-127": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982", "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986", "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992"}}}},
	"MS16-128": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7855"}}}},
	"MS16-134": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-0026", "CVE-2016-3332", "CVE-2016-3333", "CVE-2016-3334", "CVE-2016-3335", "CVE-2016-3338", "CVE-2016-3340", "CVE-2016-3342", "CVE-2016-3343", "CVE-2016-7184"}}}},
	"MS16-137": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7220", "CVE-2016-7237", "CVE-2016-7238"}}}},
	"MS16-141": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860", "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864", "CVE-2016-7865"}}}},
	"MS16-148": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7257", "CVE-2016-7262", "CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266", "CVE-2016-7267", "CVE-2016-7268", "CVE-2016-7274", "CVE-2016-7275", "CVE-2016-7276", "CVE-2016-7277", "CVE-2016-7289", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7298", "CVE-2016-7300"}}}},
	"MS16-154": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870", "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874", "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878", "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890", "CVE-2016-7892"}}}},
	"MS17-003": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2925", "CVE-2017-2926", "CVE-2017-2927", "CVE-2017-2928", "CVE-2017-2930", "CVE-2017-2931", "CVE-2017-2932", "CVE-2017-2933", "CVE-2017-2934", "CVE-2017-2935", "CVE-2017-2936", "CVE-2017-2937"}}}},
	"MS17-005": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2982", "CVE-2017-2984", "CVE-2017-2985", "CVE-2017-2986", "CVE-2017-2987", "CVE-2017-2988", "CVE-2017-2990", "CVE-2017-2991", "CVE-2017-2992", "CVE-2017-2993", "CVE-2017-2994", "CVE-2017-2995", "CVE-2017-2996"}}}},
	"MS17-007": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-0009", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012", "CVE-2017-0015", "CVE-2017-0017", "CVE-2017-0023", "CVE-2017-0032", "CVE-2017-0033", "CVE-2017-0034", "CVE-2017-0035", "CVE-2017-0037", "CVE-2017-0065", "CVE-2017-0066", "CVE-2017-0067", "CVE-2017-0068", "CVE-2017-0069", "CVE-2017-0070", "CVE-2017-0071", "CVE-2017-0094", "CVE-2017-0131", "CVE-2017-0132", "CVE-2017-0133", "CVE-2017-0134", "CVE-2017-0135", "CVE-2017-0136", "CVE-2017-0137", "CVE-2017-0138", "CVE-2017-0140", "CVE-2017-0141", "CVE-2017-0150", "CVE-2017-0151"}}}},
	"MS17-011": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0084", "CVE-2017-0085", "CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089", "CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111", "CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115", "CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0118", "CVE-2017-0119", "CVE-2017-0120", "CVE-2017-0121", "CVE-2017-0122", "CVE-2017-0123", "CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127", "CVE-2017-0128"}}}},
	"MS17-017": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-0050", "CVE-2017-0101", "CVE-2017-0102", "CVE-2017-0103"}}}},
	"MS17-023": {CVEAdjustments: []cveAdjustment{{Add: []string{"CVE-2017-2997", "CVE-2017-2998", "CVE-2017-2999", "CVE-2017-3000", "CVE-2017-3001", "CVE-2017-3002", "CVE-2017-3003"}}}},
}

// lookupAmendment returns the amendment record for a row's bulletin, or
// the zero value if the bulletin has no amendments. Bulletin IDs are
// matched case-insensitively (markdown filenames and xlsx labels diverge
// in casing for some bulletins).
func lookupAmendment(bulletinID string) bulletinArchiveAmendment {
	return bulletinArchiveAmendments[strings.ToUpper(bulletinID)]
}

// matchesRow reports whether a cveAdjustment's selector matches the given
// row. componentKey is the result of normalizeArchiveComponentKey for the
// row; the caller is expected to compute it once per row and pass it in
// to avoid recomputation across multiple adjustments.
func (a cveAdjustment) matchesRow(row bulletin.Bulletin, componentKey string) bool {
	if a.KB != "" && a.KB != row.ComponentKB {
		return false
	}
	if a.Component != "" && a.Component != componentKey {
		return false
	}
	return true
}
