package util

import (
	"slices"
	"strings"

	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersedesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersedes"
)

// canonicalProductNames maps variant product names to a single canonical name.
var canonicalProductNames = map[string]string{
	// CVRF product renames
	"Hub Device Client SDK for Azure IoT":                   "Azure IoT Hub Device Client SDK",
	"Outlook for iOS":                                       "Microsoft Outlook for iOS",
	"Service Fabric":                                        "Azure Service Fabric",
	"Dynamics 365 Business Central 2019 Spring Update":      "Dynamics 365 Business Central Spring 2019 Update",
	"Windows 11 for x64-based Systems":                      "Windows 11 Version 21H2 for x64-based Systems",
	"Windows 11 for ARM64-based Systems":                    "Windows 11 Version 21H2 for ARM64-based Systems",
	"Windows 11 Version 25H2 for ARM Systems":               "Windows 11 Version 25H2 for ARM64-based Systems",
	"Windows 11 Version 26H1 for x64-based Systems - extra": "Windows 11 Version 26H1 for x64-based Systems",
	"Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 Version 26H1 for x64-based Systems - extra": "Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 Version 26H1 for x64-based Systems",
	"Microsoft Defender for Endpoint for Windows on Windows Server 2022 Datacenter: Azure Edition":    "Microsoft Defender for Endpoint for Windows on Windows Server 2022",
	"System Center Operations Manager (SCOM) 2019":                                                    "System Center Operations Manager 2019",
	"System Center Operations Manager (SCOM) 2022":                                                    "System Center Operations Manager 2022",
	"Microsoft Teams for Mac, Classic Edition":                                                        "Microsoft Teams for Mac",
	"Microsoft Teams for Mac, New Edition":                                                            "Microsoft Teams for Mac",
	"Azure File Sync v18":                                                                             "Azure File Sync v18.0",
	"Windows Defender Antimalware Platform":                                                           "Microsoft Defender Antimalware Platform",
	// The bare name (no "on Windows ..." suffix, 2026-Oct, CVE-2026-105726) carries
	// the antimalware platform version (e.g. 4.18.26060.3008), not an OS build.
	"Microsoft Defender for Endpoint for Windows": "Microsoft Defender Antimalware Platform",
	// 2026-Oct spells the SQL Server 2017 CU31 and 2019 CU32 entries without the
	// space; they are the same CUs earlier months listed as "(CU 31)" / "(CU 32)"
	// (2017 since 2023-Feb), so keep one package name. CUs that only ever appeared
	// unspaced (2022 CU27, 2025 CU9) are listed directly in buildFixedBuildCriterion.
	"Microsoft SQL Server 2017 for x64-based Systems (CU31)": "Microsoft SQL Server 2017 for x64-based Systems (CU 31)",
	"Microsoft SQL Server 2019 for x64-based Systems (CU32)": "Microsoft SQL Server 2019 for x64-based Systems (CU 32)",
	// 2026-Oct re-lists Visual Studio 2019 16.11 under a new product ID without the
	// "(includes ...)" suffix; it is the same final servicing line earlier months
	// listed as "(includes 16.0 - 16.10)", so keep one package name.
	"Microsoft Visual Studio 2019 Version 16.11": "Microsoft Visual Studio 2019 Version 16.11 (includes 16.0 - 16.10)",
	// 2026-Oct renames the .NET products to "... runtime installed on <OS>" under the
	// same product IDs (e.g. 12414, 20837) earlier months published as "... installed
	// on <OS>", so keep one package name.
	".NET 8.0 runtime installed on Linux":    ".NET 8.0 installed on Linux",
	".NET 8.0 runtime installed on Mac OS":   ".NET 8.0 installed on Mac OS",
	".NET 8.0 runtime installed on Windows":  ".NET 8.0 installed on Windows",
	".NET 9.0 runtime installed on Linux":    ".NET 9.0 installed on Linux",
	".NET 9.0 runtime installed on Mac OS":   ".NET 9.0 installed on Mac OS",
	".NET 9.0 runtime installed on Windows":  ".NET 9.0 installed on Windows",
	".NET 10.0 runtime installed on Linux":   ".NET 10.0 installed on Linux",
	".NET 10.0 runtime installed on Mac OS":  ".NET 10.0 installed on Mac OS",
	".NET 10.0 runtime installed on Windows": ".NET 10.0 installed on Windows",
	".NET 11.0 runtime installed on Linux":   ".NET 11.0 installed on Linux",
	".NET 11.0 runtime installed on Mac OS":  ".NET 11.0 installed on Mac OS",
	".NET 11.0 runtime installed on Windows": ".NET 11.0 installed on Windows",

	// Bulletin→CVRF product name unification (legacy products with "Microsoft " prefix)
	"Microsoft Azure Kubernetes Service":                          "Azure Kubernetes Service",
	"Microsoft Azure Functions":                                   "Azure Functions",
	"Microsoft Windows 2000 Advanced Server":                      "Windows 2000 Advanced Server",
	"Microsoft Windows NT 4.0 Server":                             "Windows NT 4.0 Server",
	"Microsoft Windows 2000 Datacenter Server":                    "Windows 2000 Datacenter Server",
	"Microsoft Windows 2000 Server":                               "Windows 2000 Server",
	"Microsoft SQL Server 2000 Service Pack 4":                    "SQL Server 2000 Service Pack 4",
	"Microsoft SQL Server 2000 Reporting Services Service Pack 2": "SQL Server 2000 Reporting Services Service Pack 2",

	// MSUC title product name variants. Microsoft used "<OS> x64 Edition" for
	// the Preview Rollup track in a small number of legacy months (Oct 2016,
	// Mar 2017, Apr 2017) but "<OS> for x64-based Systems" elsewhere; this
	// alias lets deriveCrossTrackSupersedes pair PV ↔ SO/SM updates that
	// would otherwise land in separate (year, month, product) groups.
	"Windows Server 2008 R2 x64 Edition": "Windows Server 2008 R2 for x64-based Systems",
}

var productNameReplacer = strings.NewReplacer(
	"Windows Internet Explorer", "Internet Explorer",
	"Microsoft Internet Explorer", "Internet Explorer",
	"Microsoft Office Online Server", "Office Online Server",
	"Microsoft Internet Information Services", "Internet Information Services",
	"Microsoft Windows Messenger", "Windows Messenger",
	"Microsoft Windows Media Player", "Windows Media Player",
	" systems", " Systems",
	"(Server Core Installation)", "(Server Core installation)",
	"(server core installation)", "(Server Core installation)",
	" version ", " Version ",
	"-Based ", "-based ",
)

// NormalizeProductName normalizes whitespace and maps variant product names to a canonical form.
func NormalizeProductName(s string) string {
	n := productNameReplacer.Replace(strings.Join(strings.Fields(s), " "))
	if canonical, ok := canonicalProductNames[n]; ok {
		return canonical
	}
	return n
}

// DeriveSupersedes populates Supersedes by inverting SupersededBy across
// the provided KB collection. Both KB-level (KBID only) and Update-level
// (KBID + UpdateID) supersession are handled. kbs is modified in place.
func DeriveSupersedes(kbs []microsoftkbTypes.KB) {
	idx := make(map[string]*microsoftkbTypes.KB, len(kbs))
	for i := range kbs {
		idx[kbs[i].KBID] = &kbs[i]
	}

	// KB-level: if B.SupersededBy contains {KBID: A}, then A.Supersedes gets {KBID: B}.
	for i := range kbs {
		for _, sup := range kbs[i].SupersededBy {
			if sup.KBID == "" || sup.KBID == kbs[i].KBID {
				continue
			}
			supKB, ok := idx[sup.KBID]
			if !ok {
				continue
			}
			if !slices.ContainsFunc(supKB.Supersedes, func(s microsoftkbSupersedesTypes.Supersedes) bool {
				return s.KBID == kbs[i].KBID
			}) {
				supKB.Supersedes = append(supKB.Supersedes, microsoftkbSupersedesTypes.Supersedes{KBID: kbs[i].KBID})
			}
		}
	}

	// Update-level: if Update U in KB B has SupersededBy {KBID: A, UpdateID: V},
	// then Update V in KB A gets Supersedes {KBID: B, UpdateID: U.UpdateID}.
	// Key by (targetKBID, targetUpdateID) to avoid attaching Supersedes to the wrong
	// KB when the same UpdateID exists across multiple KBs.
	type updateKey struct{ KBID, UpdateID string }
	updateSupersedes := make(map[updateKey][]microsoftkbSupersedesTypes.Supersedes)
	for i := range kbs {
		for _, u := range kbs[i].Updates {
			for _, sup := range u.SupersededBy {
				if sup.KBID == "" || sup.KBID == kbs[i].KBID || sup.UpdateID == "" {
					continue
				}
				key := updateKey{KBID: sup.KBID, UpdateID: sup.UpdateID}
				updateSupersedes[key] = append(updateSupersedes[key], microsoftkbSupersedesTypes.Supersedes{
					KBID:     kbs[i].KBID,
					UpdateID: u.UpdateID,
				})
			}
		}
	}
	for i := range kbs {
		for j, u := range kbs[i].Updates {
			for _, e := range updateSupersedes[updateKey{KBID: kbs[i].KBID, UpdateID: u.UpdateID}] {
				if !slices.ContainsFunc(kbs[i].Updates[j].Supersedes, func(s microsoftkbSupersedesTypes.Supersedes) bool {
					return s.KBID == e.KBID && s.UpdateID == e.UpdateID
				}) {
					kbs[i].Updates[j].Supersedes = append(kbs[i].Updates[j].Supersedes, e)
				}
			}
		}
	}
}
