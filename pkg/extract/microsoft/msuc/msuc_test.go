package msuc_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/msuc"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	microsoftkbSupersedesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersedes"
	microsoftkbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/update"
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
			args: "./testdata/fixtures/happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := msuc.Extract(tt.args, msuc.WithDir(dir), msuc.WithConcurrency(2))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
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

func TestDeriveCrossTrackSupersedes(t *testing.T) {
	type args struct {
		kbs []microsoftkbTypes.KB
	}
	tests := []struct {
		name string
		args args
		want []microsoftkbTypes.KB
	}{
		{
			name: "Preview ⊇ SecurityMonthly ⊇ SecurityOnly (Server 2008 R2 2018-02)",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "4074598",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-So", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB4074598)"},
					},
				},
				{
					KBID: "4074594",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-Sm", Title: "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB4074594)"},
					},
				},
				{
					KBID: "4075211",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-Pv", Title: "2018-02 Preview of Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB4075211)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "4074594",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:     "U-Sm",
							Title:        "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB4074594)",
							SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "4075211", UpdateID: "U-Pv"}},
							Supersedes:   []microsoftkbSupersedesTypes.Supersedes{{KBID: "4074598", UpdateID: "U-So"}},
						},
					},
				},
				{
					KBID: "4074598",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:     "U-So",
							Title:        "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB4074598)",
							SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "4074594", UpdateID: "U-Sm"}, {KBID: "4075211", UpdateID: "U-Pv"}},
						},
					},
				},
				{
					KBID: "4075211",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:   "U-Pv",
							Title:      "2018-02 Preview of Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB4075211)",
							Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "4074594", UpdateID: "U-Sm"}, {KBID: "4074598", UpdateID: "U-So"}},
						},
					},
				},
			},
		},
		{
			name: "CumulativePreview ⊇ Cumulative (Win10 1607 2019-02)",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "4480973",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-C", Title: "2019-02 Cumulative Update for Windows 10 Version 1607 for x64-based Systems (KB4480973)"},
					},
				},
				{
					KBID: "4485447",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-Cp", Title: "2019-02 Cumulative Update Preview for Windows 10 Version 1607 for x64-based Systems (KB4485447)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "4480973",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:     "U-C",
							Title:        "2019-02 Cumulative Update for Windows 10 Version 1607 for x64-based Systems (KB4480973)",
							SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "4485447", UpdateID: "U-Cp"}},
						},
					},
				},
				{
					KBID: "4485447",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:   "U-Cp",
							Title:      "2019-02 Cumulative Update Preview for Windows 10 Version 1607 for x64-based Systems (KB4485447)",
							Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "4480973", UpdateID: "U-C"}},
						},
					},
				},
			},
		},
		{
			name: "different month: no cross-track edges added",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-03 Preview of Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-03 Preview of Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)"},
					},
				},
			},
		},
		{
			name: "different product: no cross-track edges added",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Preview of Monthly Quality Rollup for Windows 7 for x64-based Systems (KB1002)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Preview of Monthly Quality Rollup for Windows 7 for x64-based Systems (KB1002)"},
					},
				},
			},
		},
		{
			name: "product name normalization (\" version \" → \" Version \") groups together",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2019-02 Cumulative Update for Windows 10 version 1607 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2019-02 Cumulative Update Preview for Windows 10 Version 1607 for x64-based Systems (KB1002)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:     "U-A",
							Title:        "2019-02 Cumulative Update for Windows 10 version 1607 for x64-based Systems (KB1001)",
							SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "B", UpdateID: "U-B"}},
						},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:   "U-B",
							Title:      "2019-02 Cumulative Update Preview for Windows 10 Version 1607 for x64-based Systems (KB1002)",
							Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "A", UpdateID: "U-A"}},
						},
					},
				},
			},
		},
		{
			name: "non-monthly title (e.g. .NET Framework) ignored",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "Security and Quality Rollup for .NET Framework 3.5.1 on Windows 7 SP1 (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Preview of Monthly Quality Rollup for Windows 7 for x64-based Systems (KB1002)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "Security and Quality Rollup for .NET Framework 3.5.1 on Windows 7 SP1 (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Preview of Monthly Quality Rollup for Windows 7 for x64-based Systems (KB1002)"},
					},
				},
			},
		},
		{
			name: "preexisting Supersedes/SupersededBy preserved (no duplicate added)",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID:       "B",
					Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "A"}},
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)"},
					},
				},
				{
					KBID:         "A",
					SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "B"}},
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-A", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID:         "A",
					SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "B"}},
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:     "U-A",
							Title:        "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)",
							SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "B", UpdateID: "U-B"}},
						},
					},
				},
				{
					KBID:       "B",
					Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "A"}},
					Updates: []microsoftkbUpdateTypes.Update{
						{
							UpdateID:   "U-B",
							Title:      "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)",
							Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "A", UpdateID: "U-A"}},
						},
					},
				},
			},
		},
		{
			name: "empty UpdateID skipped (no malformed edges synthesized)",
			args: args{kbs: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)"},
					},
				},
			}},
			want: []microsoftkbTypes.KB{
				{
					KBID: "A",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "", Title: "2018-02 Security Only Quality Update for Windows Server 2008 R2 for x64-based Systems (KB1001)"},
					},
				},
				{
					KBID: "B",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U-B", Title: "2018-02 Security Monthly Quality Rollup for Windows Server 2008 R2 for x64-based Systems (KB1002)"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msuc.DeriveCrossTrackSupersedes(tt.args.kbs)
			if diff := cmp.Diff(tt.want, tt.args.kbs,
				cmpopts.SortSlices(func(x, y microsoftkbTypes.KB) bool { return microsoftkbTypes.Compare(x, y) < 0 }),
				cmpopts.SortSlices(func(x, y microsoftkbUpdateTypes.Update) bool { return microsoftkbUpdateTypes.Compare(x, y) < 0 }),
				cmpopts.SortSlices(func(x, y microsoftkbSupersededByTypes.SupersededBy) bool {
					return microsoftkbSupersededByTypes.Compare(x, y) < 0
				}),
				cmpopts.SortSlices(func(x, y microsoftkbSupersedesTypes.Supersedes) bool {
					return microsoftkbSupersedesTypes.Compare(x, y) < 0
				}),
			); diff != "" {
				t.Errorf("msuc.DeriveCrossTrackSupersedes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
