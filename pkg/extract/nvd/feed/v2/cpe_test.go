package v2

import (
	"testing"

	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

func TestNormalizeCiscoVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple paren",
			input:    "12.5(1)",
			expected: "12.5.1",
		},
		{
			name:     "paren with suffix",
			input:    "9.8(4)15",
			expected: "9.8.4.15",
		},
		{
			name:     "nested dot in paren",
			input:    "3.2(11.5)",
			expected: "3.2.11.5",
		},
		{
			name:     "multiple parens",
			input:    "12.4(25e)ja1",
			expected: "12.4.25e.ja1",
		},
		{
			name:     "no parens passthrough",
			input:    "7.1.2",
			expected: "7.1.2",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "complex Cisco IOS",
			input:    "15.1(4)m12c",
			expected: "15.1.4.m12c",
		},
		{
			name:     "version with _es suffix",
			input:    "12.6(1)_es1",
			expected: "12.6.1._es1",
		},
		{
			name:     "Zyxel firmware style",
			input:    `3.40\(agd.2\)`,
			expected: `3.40\.agd.2\`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCiscoVersion(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeCiscoVersion(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsSemver(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "simple semver", input: "1.2.3", expected: true},
		{name: "two component", input: "1.2", expected: true},
		{name: "single component", input: "1", expected: true},
		{name: "four component", input: "1.2.3.4", expected: true},
		{name: "empty", input: "", expected: false},
		{name: "wildcard", input: "*", expected: false},
		{name: "dash", input: "-", expected: false},
		{name: "cisco paren", input: "12.5(1)", expected: false},
		{name: "with prerelease", input: "1.0.9-8", expected: true},
		{name: "zyxel escaped", input: `4.70\(abhs.5\)c0`, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSemver(tt.input)
			if got != tt.expected {
				t.Errorf("IsSemver(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestProductVariants(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		product  string // WFN-escaped form
		expected []string
	}{
		{
			name:     "underscore product",
			vendor:   "cisco",
			product:  "nx_os", // WFN: no escaping for underscore
			expected: []string{"cisco:nx_os", `cisco:nx\-os`},
		},
		{
			name:     "hyphen product (WFN-escaped)",
			vendor:   "cisco",
			product:  `nx\-os`, // WFN-escaped hyphen
			expected: []string{`cisco:nx\-os`, "cisco:nx_os"},
		},
		{
			name:     "no special chars",
			vendor:   "cisco",
			product:  "ios",
			expected: []string{"cisco:ios"},
		},
		{
			name:     "multiple underscores",
			vendor:   "cisco",
			product:  "ios_xe_sd_wan",
			expected: []string{"cisco:ios_xe_sd_wan", `cisco:ios\-xe\-sd\-wan`},
		},
		{
			name:     "WFN-escaped hyphen product pan-os",
			vendor:   "paloaltonetworks",
			product:  `pan\-os`,
			expected: []string{`paloaltonetworks:pan\-os`, "paloaltonetworks:pan_os"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := productVariants(tt.vendor, tt.product)
			if len(got) != len(tt.expected) {
				t.Fatalf("productVariants(%q, %q) returned %d variants, want %d: %v",
					tt.vendor, tt.product, len(got), len(tt.expected), got)
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("productVariants(%q, %q)[%d] = %q, want %q",
						tt.vendor, tt.product, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestIndexKey(t *testing.T) {
	tests := []struct {
		name     string
		cpe      string
		expected string
		wantErr  bool
	}{
		{
			name:     "exact version",
			cpe:      "cpe:2.3:a:cisco:ios_xr:7.1.2:*:*:*:*:*:*:*",
			expected: "a:cisco:ios_xr:7.1.2",
		},
		{
			name:     "wildcard version",
			cpe:      "cpe:2.3:o:cisco:ios_xr:*:*:*:*:*:*:*:*",
			expected: "o:cisco:ios_xr:ANY",
		},
		{
			name:     "hardware part with specific version",
			cpe:      "cpe:2.3:h:cisco:nexus_9000:1.0:*:*:*:*:*:*:*",
			expected: "h:cisco:nexus_9000:1.0",
		},
		{
			name:     "application with dash in version",
			cpe:      "cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*",
			expected: "a:google:chrome:120.0.6099.109",
		},
		{
			name:    "invalid CPE",
			cpe:     "not-a-cpe",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IndexKey(tt.cpe)
			if tt.wantErr {
				if err == nil {
					t.Errorf("IndexKey(%q) should error but got %q", tt.cpe, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("IndexKey(%q) unexpected error: %v", tt.cpe, err)
			}
			if got != tt.expected {
				t.Errorf("IndexKey(%q) = %q, want %q", tt.cpe, got, tt.expected)
			}
		})
	}
}

func TestDecideRangeType(t *testing.T) {
	tests := []struct {
		name     string
		match    cveTypes.CPEMatch
		expected rangeTypes.RangeType
	}{
		{
			name: "all semver endpoints",
			match: cveTypes.CPEMatch{
				VersionStartIncluding: "1.0.0",
				VersionEndExcluding:   "2.0.0",
			},
			expected: rangeTypes.RangeTypeSEMVER,
		},
		{
			name: "only end semver",
			match: cveTypes.CPEMatch{
				VersionEndExcluding: "6.7.0",
			},
			expected: rangeTypes.RangeTypeSEMVER,
		},
		{
			name: "cisco paren endpoint",
			match: cveTypes.CPEMatch{
				VersionEndIncluding: "12.8(1)",
			},
			expected: rangeTypes.RangeTypeUnknown,
		},
		{
			name: "escaped paren endpoint",
			match: cveTypes.CPEMatch{
				VersionEndExcluding: `4.70\(abhs.5\)c0`,
			},
			expected: rangeTypes.RangeTypeUnknown,
		},
		{
			name:     "no endpoints (exact match)",
			match:    cveTypes.CPEMatch{},
			expected: rangeTypes.RangeTypeSEMVER,
		},
		{
			name: "mixed semver and non-semver",
			match: cveTypes.CPEMatch{
				VersionStartIncluding: "1.0.0",
				VersionEndExcluding:   "12.5(1)",
			},
			expected: rangeTypes.RangeTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideRangeType(tt.match)
			if got != tt.expected {
				t.Errorf("decideRangeType() = %v, want %v", got, tt.expected)
			}
		})
	}
}
