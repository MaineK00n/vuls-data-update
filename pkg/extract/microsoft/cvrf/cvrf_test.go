package cvrf_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/cvrf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestBuildFixedBuildCriterion(t *testing.T) {
	tests := []struct {
		name        string
		cveID       string
		productName string
		fixedBuild  string
		wantNil     bool
		wantErr     bool
	}{
		{
			name:        "SQL Server 2022 CU 24",
			cveID:       "CVE-2026-32176",
			productName: "Microsoft SQL Server 2022 for x64-based Systems (CU 24)",
			fixedBuild:  "16.0.4250.1",
		},
		{
			name:        "SQL Server 2025 CU3",
			cveID:       "CVE-2026-32176",
			productName: "Microsoft SQL Server 2025 for x64-based Systems (CU3)",
			fixedBuild:  "17.0.4030.1",
		},
		{
			name:        "Microsoft Defender Antimalware Platform",
			cveID:       "CVE-2026-33825",
			productName: "Microsoft Defender Antimalware Platform",
			fixedBuild:  "4.18.26030.3011",
		},
		{
			name:        "CVE-2026-32077 Windows Server 2012 R2 IE Cumulative 1.000 skipped",
			cveID:       "CVE-2026-32077",
			productName: "Windows Server 2012 R2",
			fixedBuild:  "1.000",
			wantNil:     true,
		},
		{
			name:        "CVE-2026-32077 Windows Server 2012 R2 Server Core IE Cumulative 1.000 skipped",
			cveID:       "CVE-2026-32077",
			productName: "Windows Server 2012 R2 (Server Core installation)",
			fixedBuild:  "1.000",
			wantNil:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cvrf.BuildFixedBuildCriterion(tt.cveID, tt.productName, tt.fixedBuild)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFixedBuildCriterion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantNil && got != nil {
				t.Errorf("BuildFixedBuildCriterion() = %v, want nil", got)
			}
			if !tt.wantNil && !tt.wantErr && got == nil {
				t.Errorf("BuildFixedBuildCriterion() = nil, want non-nil Criterion")
			}
		})
	}
}

func TestFixedBuildOverrides(t *testing.T) {
	overrides := cvrf.FixedBuildOverrides
	entries := [][3]string{
		{"CVE-2026-32077", "Windows Server 2012 R2", "1.000"},
		{"CVE-2026-32077", "Windows Server 2012 R2 (Server Core installation)", "1.000"},
	}
	for _, key := range entries {
		t.Run(key[0]+"/"+key[1], func(t *testing.T) {
			got, ok := overrides[key]
			if !ok {
				t.Errorf("fixedBuildOverrides missing entry %v", key)
				return
			}
			if got != "" {
				t.Errorf("fixedBuildOverrides[%v] = %q, want empty string (skip)", key, got)
			}
		})
	}
}

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
			err := cvrf.Extract(tt.args, cvrf.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
