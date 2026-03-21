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
	"Microsoft Defender for Endpoint for Windows on Windows Server 2022 Datacenter: Azure Edition": "Microsoft Defender for Endpoint for Windows on Windows Server 2022",
	"System Center Operations Manager (SCOM) 2019":                                                 "System Center Operations Manager 2019",
	"System Center Operations Manager (SCOM) 2022":                                                 "System Center Operations Manager 2022",
	"Microsoft Teams for Mac, Classic Edition":                                                     "Microsoft Teams for Mac",
	"Microsoft Teams for Mac, New Edition":                                                         "Microsoft Teams for Mac",
	"Azure File Sync v18":                                                                          "Azure File Sync v18.0",
}

var productNameReplacer = strings.NewReplacer(
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
