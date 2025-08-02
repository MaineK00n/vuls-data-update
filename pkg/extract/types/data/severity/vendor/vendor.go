package vendor

import (
	"cmp"
	"strings"
)

func rank(src, s string) int {
	switch src {
	case "errata.almalinux.org", "secalert@redhat.com", "errata.rockylinux.org":
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 4
		case "IMPORTANT":
			return 3
		case "MODERATE":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	case "linux-security@amazon.com":
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 4
		case "IMPORTANT":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	case "security.archlinux.org":
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 5
		case "HIGH":
			return 4
		case "MEDIUM":
			return 3
		case "LOW":
			return 2
		case "UNKNOWN":
			return 1
		default:
			return 0
		}
	case "linux.oracle.com/security":
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 5
		case "IMPORTANT":
			return 4
		case "MODERATE":
			return 3
		case "LOW":
			return 2
		case "N/A":
			return 1
		default:
			return 0
		}
	case "launchpad.net/ubuntu-cve-tracker":
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 5
		case "HIGH":
			return 4
		case "MEDIUM":
			return 3
		case "LOW":
			return 2
		case "NEGLIGIBLE":
			return 1
		default:
			return 0
		}
	default:
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 6
		case "HIGH", "IMPORTANT":
			return 5
		case "MEDIUM", "MODERATE":
			return 4
		case "LOW":
			return 3
		case "NEGLIGIBLE":
			return 2
		case "UNKNOWN", "N/A":
			return 1
		default:
			return 0
		}
	}
}

func Compare(source, x, y string) int {
	return cmp.Compare(rank(source, x), rank(source, y))
}
