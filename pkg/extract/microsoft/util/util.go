package util

import "strings"

// canonicalProductNames maps variant product names to a single canonical name.
var canonicalProductNames = map[string]string{
	// CVRF product renames
	"Hub Device Client SDK for Azure IoT":              "Azure IoT Hub Device Client SDK",
	"Outlook for iOS":                                  "Microsoft Outlook for iOS",
	"Service Fabric":                                   "Azure Service Fabric",
	"Dynamics 365 Business Central 2019 Spring Update": "Dynamics 365 Business Central Spring 2019 Update",
	"Windows 11 for x64-based Systems":                 "Windows 11 Version 21H2 for x64-based Systems",
	"Windows 11 for ARM64-based Systems":               "Windows 11 Version 21H2 for ARM64-based Systems",
	"Windows 11 Version 25H2 for ARM Systems":          "Windows 11 Version 25H2 for ARM64-based Systems",
	"Microsoft Defender for Endpoint for Windows on Windows Server 2022 Datacenter: Azure Edition": "Microsoft Defender for Endpoint for Windows on Windows Server 2022",
	"System Center Operations Manager (SCOM) 2019":                                                 "System Center Operations Manager 2019",
	"System Center Operations Manager (SCOM) 2022":                                                 "System Center Operations Manager 2022",
	"Microsoft Teams for Mac, Classic Edition":                                                     "Microsoft Teams for Mac",
	"Microsoft Teams for Mac, New Edition":                                                         "Microsoft Teams for Mac",
	"Azure File Sync v18":                                                                          "Azure File Sync v18.0",
	"Windows Defender Antimalware Platform":                                                        "Microsoft Defender Antimalware Platform",

	// Bulletin→CVRF product name unification (legacy products with "Microsoft " prefix)
	"Microsoft Azure Kubernetes Service":                          "Azure Kubernetes Service",
	"Microsoft Azure Functions":                                   "Azure Functions",
	"Microsoft Windows 2000 Advanced Server":                      "Windows 2000 Advanced Server",
	"Microsoft Windows NT 4.0 Server":                             "Windows NT 4.0 Server",
	"Microsoft Windows 2000 Datacenter Server":                    "Windows 2000 Datacenter Server",
	"Microsoft Windows 2000 Server":                               "Windows 2000 Server",
	"Microsoft SQL Server 2000 Service Pack 4":                    "SQL Server 2000 Service Pack 4",
	"Microsoft SQL Server 2000 Reporting Services Service Pack 2": "SQL Server 2000 Reporting Services Service Pack 2",
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
