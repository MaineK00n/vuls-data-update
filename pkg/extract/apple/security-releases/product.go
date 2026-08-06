package securityreleases

import (
	"regexp"
	"strings"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
)

// releasePatterns positively matches the release names that map to a CPE:
// the OS families and Safari. The marketing names are enumerated so that
// lookalikes such as "OS X NTP Security Update 1.0" or "macOS Server 5.2"
// never match, and the version must close the name so that derived releases
// such as "macOS Catalina 10.15.7 Supplemental Update" fall through. Names
// outside these patterns (applications, firmware, "Security Update
// YYYY-NNN", ...) yield no detection on purpose: the advisory and
// vulnerability contents are still extracted, and widening the detection
// scope is a matter of adding patterns here.
var releasePatterns = []struct {
	re  *regexp.Regexp
	cpe string
}{
	{regexp.MustCompile(`^macOS(?: (?:Sierra|High Sierra|Mojave|Catalina|Big Sur|Monterey|Ventura|Sonoma|Sequoia|Tahoe))? v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^(?:Mac )?OS X(?: (?:Lion|Mountain Lion|Mavericks|Yosemite|El Capitan))? v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^iOS v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^iPadOS v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^(?:watchOS|Watch OS) v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:watchos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^tvOS v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^visionOS v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:o:apple:visionos:*:*:*:*:*:*:*:*"},
	{regexp.MustCompile(`^Safari v?([0-9][0-9.]*[0-9]|[0-9])(?: \([a-z]\))?$`), "cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*"},
}

// releaseNameSeparators split a combined release name such as
// "macOS High Sierra 10.13.2, Security Update 2017-002 Sierra, and Security
// Update 2017-005 El Capitan" or "iOS 26.6 and iPadOS 26.6" into its parts.
var releaseNameSeparators = regexp.MustCompile(`, and |; and |, |; | and | / `)

// releaseCriterions maps a release name to CPE criterions, one per part of
// the name that names an OS release or Safari: the release fixes the listed
// vulnerabilities, so versions below it are vulnerable.
func releaseCriterions(name string) []criterionTypes.Criterion {
	var cs []criterionTypes.Criterion
	for _, part := range releaseNameSeparators.Split(name, -1) {
		// a trailing asterisk is a footnote marker, e.g. "Safari 14.1*"
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), "*"))
		for _, p := range releasePatterns {
			m := p.re.FindStringSubmatch(part)
			if m == nil {
				continue
			}
			cs = append(cs, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					CPE:        ccTypes.CPE(p.cpe),
					Range: &ccRangeTypes.Range{
						Type:     ccRangeTypes.RangeTypeVersion,
						LessThan: m[1],
					},
					Fixed: []string{m[1]},
				},
			})
			break
		}
	}
	return cs
}
