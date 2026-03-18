package v2

import (
	"regexp"
	"strings"

	"github.com/hashicorp/go-version"
)

// ciscoParenRe matches Cisco-style parenthesized version components.
// Examples:
//
//	"9.8(4)15"    → "9.8.4.15"
//	"12.5(1)"     → "12.5.1"
//	"3.2(11.5)"   → "3.2.11.5"
var ciscoParenRe = regexp.MustCompile(`\(([^)]*)\)`)

// NormalizeCiscoVersion converts Cisco-style parenthesized version notation
// to dot-separated notation.
//
//	"12.5(1)"     → "12.5.1"
//	"9.8(4)15"    → "9.8.4.15"
//	"3.2(11.5)"   → "3.2.11.5"
//	"7.1.2"       → "7.1.2"  (no change if no parens)
func NormalizeCiscoVersion(v string) string {
	if !strings.Contains(v, "(") {
		return v
	}
	// Replace each "(X)" with ".X." to ensure dots on both sides
	result := ciscoParenRe.ReplaceAllString(v, ".$1.")
	// Clean up potential double dots and trailing dots
	for strings.Contains(result, "..") {
		result = strings.ReplaceAll(result, "..", ".")
	}
	result = strings.Trim(result, ".")
	return result
}

// IsSemver checks if a version string is parseable as semver
// using hashicorp/go-version.
func IsSemver(v string) bool {
	if v == "" || v == "*" || v == "-" {
		return false
	}
	_, err := version.NewSemver(v)
	return err == nil
}
