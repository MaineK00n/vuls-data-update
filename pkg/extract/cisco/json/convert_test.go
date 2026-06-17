package json_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/cisco/json"
)

func TestConvertProductName(t *testing.T) {
	tests := []struct {
		name     string
		product  string
		want     string
		hasError bool
	}{
		{
			name:    "asa exact version",
			product: "Cisco Adaptive Security Appliance (ASA) Software 9.20.1",
			want:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.20.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "secure firewall asa rename maps to same product",
			product: "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software 9.20.1",
			want:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.20.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "nx-os version with parens is escaped",
			product: "Cisco NX-OS Software 10.1(1)",
			want:    `cpe:2.3:o:cisco:nx-os:10.1\(1\):*:*:*:*:*:*:*`,
		},
		{
			name:    "skip value Base yields empty",
			product: "Cisco Adaptive Security Appliance (ASA) Software Base",
			want:    "",
		},
		{
			name:    "unknown family yields empty",
			product: "Cisco Identity Services Engine 3.1.0",
			want:    "",
		},
		{
			name:    "known unparseable product name is skipped",
			product: "Cisco IOS XE Software .0",
			want:    "",
		},
		{
			name:    "known unparseable WLC build is skipped",
			product: "Cisco Wireless LAN Controller (WLC) 3.6.0E",
			want:    "",
		},
		{
			name:     "unknown unparseable version errors",
			product:  "Cisco Wireless LAN Controller (WLC) 9.9.9Z",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.ConvertProductName(tt.product)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("ConvertProductName(%q) unexpected error: %v", tt.product, err)
			case err == nil && tt.hasError:
				t.Errorf("ConvertProductName(%q) expected error, got %q", tt.product, got)
			case err == nil && got != tt.want:
				t.Errorf("ConvertProductName(%q) = %q, want %q", tt.product, got, tt.want)
			}
		})
	}
}
