package json_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/cisco/json"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := json.Extract(tt.args, json.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

func TestConvertProductName(t *testing.T) {
	tests := []struct {
		name         string
		product      string
		wantBase     string
		wantConcrete string
		hasError     bool
	}{
		{
			name:         "asa exact version",
			product:      "Cisco Adaptive Security Appliance (ASA) Software 9.20.1",
			wantBase:     "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
			wantConcrete: "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.20.1.0:*:*:*:*:*:*:*",
		},
		{
			name:         "secure firewall asa rename maps to same product",
			product:      "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software 9.20.1",
			wantBase:     "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
			wantConcrete: "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.20.1.0:*:*:*:*:*:*:*",
		},
		{
			name:         "nx-os version with parens is escaped",
			product:      "Cisco NX-OS Software 10.1(1)",
			wantBase:     "cpe:2.3:o:cisco:nx-os:*:*:*:*:*:*:*:*",
			wantConcrete: `cpe:2.3:o:cisco:nx-os:10.1\(1\):*:*:*:*:*:*:*`,
		},
		{
			name:    "skip value Base yields empty",
			product: "Cisco Adaptive Security Appliance (ASA) Software Base",
		},
		{
			name:    "unknown family yields empty",
			product: "Cisco Identity Services Engine 3.1.0",
		},
		{
			name:    "known unparseable product name is skipped",
			product: "Cisco IOS XE Software .0",
		},
		{
			name:    "known unparseable WLC build is skipped",
			product: "Cisco Wireless LAN Controller (WLC) 3.6.0E",
		},
		{
			name:    "known truncated IOS XE version is skipped",
			product: "Cisco IOS XE Software (3)S2.1",
		},
		{
			name:    "known IOS XG typo family is skipped",
			product: "Cisco IOS XG Software ",
		},
		{
			name:    "IOS XR family-level Base entry is skipped",
			product: "Cisco IOS XR Software Base",
		},
		{
			name:    "known unparseable IOS XR build is skipped",
			product: "Cisco IOS XR Software 5.1.1.K9SEC",
		},
		{
			name:    "known four-part IOS XR name is skipped",
			product: "Cisco IOS XR Software 6.0.2.01",
		},
		{
			name:    "known FTD hotfix placeholder is skipped",
			product: "Cisco Secure Firewall Threat Defense (FTD) Software 6.2.1 Hotfix",
		},
		{
			name:         "asa ED designator is stripped",
			product:      "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software 9.0.1.ED",
			wantBase:     "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
			wantConcrete: "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.0.1.0:*:*:*:*:*:*:*",
		},
		{
			name:         "asa SMP.ED designators are stripped",
			product:      "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software 9.1.6.SMP.ED",
			wantBase:     "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
			wantConcrete: "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.1.6.0:*:*:*:*:*:*:*",
		},
		{
			name:         "asa SMP designator on a four-part release is stripped",
			product:      "Cisco Adaptive Security Appliance (ASA) Software 9.2.2.4.SMP",
			wantBase:     "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
			wantConcrete: "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.2.2.4:*:*:*:*:*:*:*",
		},
		{
			name:     "asa unknown letter suffix still errors",
			product:  "Cisco Adaptive Security Appliance (ASA) Software 9.1.6.FOO",
			hasError: true,
		},
		{
			name:     "unknown unparseable version errors",
			product:  "Cisco Wireless LAN Controller (WLC) 9.9.9Z",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, concrete, err := json.ConvertProductName(tt.product)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("ConvertProductName(%q) unexpected error: %v", tt.product, err)
			case err == nil && tt.hasError:
				t.Errorf("ConvertProductName(%q) expected error, got base %q concrete %q", tt.product, base, concrete)
			case err == nil && (base != tt.wantBase || concrete != tt.wantConcrete):
				t.Errorf("ConvertProductName(%q) = (%q, %q), want (%q, %q)", tt.product, base, concrete, tt.wantBase, tt.wantConcrete)
			}
		})
	}
}
