package cvrf_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/cvrf"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestBuildFixedBuildCriterion(t *testing.T) {
	type args struct {
		cveID         string
		productName   string
		rawFixedBuild string
	}
	tests := []struct {
		name    string
		args    args
		want    *criterionTypes.Criterion
		wantErr bool
	}{
		{
			name: "SQL Server 2022 CU 24",
			args: args{
				cveID:         "CVE-2026-32176",
				productName:   "Microsoft SQL Server 2022 for x64-based Systems (CU 24)",
				rawFixedBuild: "16.0.4250.1",
			},
			want: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					Package: packageTypes.Package{
						Type:   packageTypes.PackageTypeBinary,
						Binary: &binaryTypes.Package{Name: "Microsoft SQL Server 2022 for x64-based Systems (CU 24)"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeTypes.RangeTypeMicrosoftSQLServer,
						Range: []affectedrangeTypes.Range{{LessThan: "16.0.4250.1"}},
						Fixed: []string{"16.0.4250.1"},
					},
				},
			},
		},
		{
			name: "SQL Server 2025 CU3",
			args: args{
				cveID:         "CVE-2026-32176",
				productName:   "Microsoft SQL Server 2025 for x64-based Systems (CU3)",
				rawFixedBuild: "17.0.4030.1",
			},
			want: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					Package: packageTypes.Package{
						Type:   packageTypes.PackageTypeBinary,
						Binary: &binaryTypes.Package{Name: "Microsoft SQL Server 2025 for x64-based Systems (CU3)"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeTypes.RangeTypeMicrosoftSQLServer,
						Range: []affectedrangeTypes.Range{{LessThan: "17.0.4030.1"}},
						Fixed: []string{"17.0.4030.1"},
					},
				},
			},
		},
		{
			name: "Microsoft Defender Antimalware Platform",
			args: args{
				cveID:         "CVE-2026-33825",
				productName:   "Microsoft Defender Antimalware Platform",
				rawFixedBuild: "4.18.26030.3011",
			},
			want: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					Package: packageTypes.Package{
						Type:   packageTypes.PackageTypeBinary,
						Binary: &binaryTypes.Package{Name: "Microsoft Defender Antimalware Platform"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeTypes.RangeTypeMicrosoftDefenderWindows,
						Range: []affectedrangeTypes.Range{{LessThan: "4.18.26030.3011"}},
						Fixed: []string{"4.18.26030.3011"},
					},
				},
			},
		},
		{
			name: "CVE-2026-32077 Windows Server 2012 R2 IE Cumulative 1.000 skipped",
			args: args{
				cveID:         "CVE-2026-32077",
				productName:   "Windows Server 2012 R2",
				rawFixedBuild: "1.000",
			},
			want: nil,
		},
		{
			name: "CVE-2026-32077 Windows Server 2012 R2 Server Core IE Cumulative 1.000 skipped",
			args: args{
				cveID:         "CVE-2026-32077",
				productName:   "Windows Server 2012 R2 (Server Core installation)",
				rawFixedBuild: "1.000",
			},
			want: nil,
		},
		{
			name: "Branch-leaked Win11 21H2 x64 FixedBuild applies override end-to-end (CVE-2023-21817)",
			args: args{
				cveID:         "CVE-2023-21817",
				productName:   "Windows 11 Version 21H2 for x64-based Systems",
				rawFixedBuild: "10.0.22621.1574",
			},
			want: &criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &vcTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
					Package: packageTypes.Package{
						Type:   packageTypes.PackageTypeBinary,
						Binary: &binaryTypes.Package{Name: "Windows 11 Version 21H2 for x64-based Systems"},
					},
					Affected: &affectedTypes.Affected{
						Type:  affectedrangeTypes.RangeTypeMicrosoftWindows,
						Range: []affectedrangeTypes.Range{{LessThan: "10.0.22000.1574"}},
						Fixed: []string{"10.0.22000.1574"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cvrf.BuildFixedBuildCriterion(tt.args.cveID, tt.args.productName, tt.args.rawFixedBuild)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFixedBuildCriterion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("BuildFixedBuildCriterion() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFixedBuildOverrides(t *testing.T) {
	tests := []struct {
		name string
		key  [3]string
		want string
	}{
		{
			name: "CVE-2026-32077 Windows Server 2012 R2",
			key:  [3]string{"CVE-2026-32077", "Windows Server 2012 R2", "1.000"},
			want: "",
		},
		{
			name: "CVE-2026-32077 Windows Server 2012 R2 Server Core",
			key:  [3]string{"CVE-2026-32077", "Windows Server 2012 R2 (Server Core installation)", "1.000"},
			want: "",
		},
		// Branch-leaked Windows OS FixedBuild (sibling-servicing-branch leak in
		// CVRF Vendor Fix Remediation: rewrite only the third component of "10.0.X.Y"
		// to the product's known servicing-branch build major).
		{
			name: "Win11 21H2 x64 with 22H2 build major (CVE-2023-21817)",
			key:  [3]string{"CVE-2023-21817", "Windows 11 Version 21H2 for x64-based Systems", "10.0.22621.1574"},
			want: "10.0.22000.1574",
		},
		{
			name: "Win11 21H2 ARM64 with 22H2 build major (CVE-2023-21817)",
			key:  [3]string{"CVE-2023-21817", "Windows 11 Version 21H2 for ARM64-based Systems", "10.0.22621.1574"},
			want: "10.0.22000.1574",
		},
		{
			name: "Win11 22H2 x64 with 23H2 build major (CVE-2025-59220)",
			key:  [3]string{"CVE-2025-59220", "Windows 11 Version 22H2 for x64-based Systems", "10.0.22631.5909"},
			want: "10.0.22621.5909",
		},
		{
			name: "Win11 23H2 ARM64 with 22H2 build major (CVE-2023-35628)",
			key:  [3]string{"CVE-2023-35628", "Windows 11 Version 23H2 for ARM64-based Systems", "10.0.22621.2861"},
			want: "10.0.22631.2861",
		},
		{
			name: "Win11 24H2 x64 with 22H2 build major (CVE-2023-40547)",
			key:  [3]string{"CVE-2023-40547", "Windows 11 Version 24H2 for x64-based Systems", "10.0.22621.5189"},
			want: "10.0.26100.5189",
		},
		{
			name: "Win11 25H2 ARM64 with 24H2 build major (CVE-2026-25172)",
			key:  [3]string{"CVE-2026-25172", "Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26100.7982"},
			want: "10.0.26200.7982",
		},
		{
			name: "Win Server 2025 with 25H2 build major (CVE-2025-49735)",
			key:  [3]string{"CVE-2025-49735", "Windows Server 2025", "10.0.26200.4349"},
			want: "10.0.26100.4349",
		},
		{
			name: "Win Server 2025 Server Core with 25H2 build major (CVE-2025-49735)",
			key:  [3]string{"CVE-2025-49735", "Windows Server 2025 (Server Core installation)", "10.0.26200.4349"},
			want: "10.0.26100.4349",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvrf.FixedBuildOverrides[tt.key]
			if !ok {
				t.Errorf("fixedBuildOverrides missing entry %v", tt.key)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("fixedBuildOverrides[%v] mismatch (-want +got):\n%s", tt.key, diff)
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
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}
