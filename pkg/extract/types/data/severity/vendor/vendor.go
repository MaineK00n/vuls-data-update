package vendor

import (
	"cmp"
	"slices"
	"strings"
)

func rank(src, s string) int {
	s = strings.ToUpper(s)
	return slices.IndexFunc(func() [][]string {
		switch src {
		case "errata.almalinux.org":
			return [][]string{{"NONE"}, {"LOW"}, {"MODERATE"}, {"IMPORTANT"}, {"CRITICAL"}}
		case "linux-security@amazon.com":
			return [][]string{{"LOW"}, {"MEDIUM"}, {"IMPORTANT"}, {"CRITICAL"}}
		case "security.archlinux.org":
			return [][]string{{"UNKNOWN"}, {"LOW"}, {"MEDIUM"}, {"HIGH"}, {"CRITICAL"}}
		case "fedoraproject.org":
			return [][]string{{"UNSPECIFIED"}, {"LOW"}, {"MEDIUM"}, {"HIGH"}, {"URGENT"}}
		case "linux.oracle.com/security":
			return [][]string{{"N/A"}, {"LOW"}, {"MODERATE"}, {"IMPORTANT"}, {"CRITICAL"}}
		case "secalert@redhat.com":
			return [][]string{{"LOW"}, {"MODERATE"}, {"IMPORTANT"}, {"CRITICAL"}}
		case "errata.rockylinux.org":
			return [][]string{{"UNKNOWN"}, {"LOW"}, {"MODERATE"}, {"IMPORTANT"}, {"CRITICAL"}}
		case "launchpad.net/ubuntu-cve-tracker":
			return [][]string{{"NEGLIGIBLE"}, {"LOW"}, {"MEDIUM"}, {"HIGH"}, {"CRITICAL"}}
		default:
			return [][]string{{"NONE", "UNKNOWN", "UNSPECIFIED", "N/A"}, {"NEGLIGIBLE"}, {"LOW"}, {"MEDIUM"}, {"HIGH", "IMPORTANT"}, {"CRITICAL", "URGENT"}}
		}
	}(), func(e []string) bool {
		return slices.Contains(e, s)
	})
}

func Compare(source, x, y string) int {
	return cmp.Compare(rank(source, x), rank(source, y))
}
