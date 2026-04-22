package util

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	microsoftkbSupersedesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersedes"
	microsoftkbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/update"
)

func TestNormalizeProductName(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "no change",
			args: args{s: "Windows 10 Version 1607 for x64-based Systems"},
			want: "Windows 10 Version 1607 for x64-based Systems",
		},
		{
			name: "whitespace normalization",
			args: args{s: "Windows Server 2016  (Server Core installation)"},
			want: "Windows Server 2016 (Server Core installation)",
		},
		{
			name: "systems to Systems",
			args: args{s: "Windows 8.1 for 32-bit systems"},
			want: "Windows 8.1 for 32-bit Systems",
		},
		{
			name: "Server Core Installation to installation",
			args: args{s: "Windows Server 2016 (Server Core Installation)"},
			want: "Windows Server 2016 (Server Core installation)",
		},
		{
			name: "server core installation to Server Core installation",
			args: args{s: "Windows Server 2012 R2 (server core installation)"},
			want: "Windows Server 2012 R2 (Server Core installation)",
		},
		{
			name: "version to Version",
			args: args{s: "Windows 11 version 21H2 for x64-based Systems"},
			want: "Windows 11 Version 21H2 for x64-based Systems",
		},
		{
			name: "Based to based",
			args: args{s: "Windows Server 2008 for Itanium-Based Systems Service Pack 2"},
			want: "Windows Server 2008 for Itanium-based Systems Service Pack 2",
		},
		{
			name: "canonical product name",
			args: args{s: "Hub Device Client SDK for Azure IoT"},
			want: "Azure IoT Hub Device Client SDK",
		},
		{
			name: "canonical after normalization",
			args: args{s: "Windows 11 for x64-based  Systems"},
			want: "Windows 11 Version 21H2 for x64-based Systems",
		},
		{
			name: "multiple rules combined",
			args: args{s: "Windows Server, version 1709  (Server Core Installation)"},
			want: "Windows Server, Version 1709 (Server Core installation)",
		},
		{
			name: "Windows Internet Explorer prefix stripped",
			args: args{s: "Windows Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1"},
			want: "Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1",
		},
		{
			name: "Microsoft Internet Explorer prefix stripped",
			args: args{s: "Microsoft Internet Explorer 6.0 on Microsoft Windows XP Service Pack 3"},
			want: "Internet Explorer 6.0 on Microsoft Windows XP Service Pack 3",
		},
		{
			name: "plain Internet Explorer unchanged",
			args: args{s: "Internet Explorer 11 on Windows 10 for x64-based Systems"},
			want: "Internet Explorer 11 on Windows 10 for x64-based Systems",
		},
		{
			name: "Microsoft Office Online Server prefix stripped",
			args: args{s: "Microsoft Office Online Server"},
			want: "Office Online Server",
		},
		{
			name: "Microsoft IIS prefix stripped with suffix",
			args: args{s: "Microsoft Internet Information Services 7.5 on Windows Server 2008 R2 for x64-based Systems Service Pack 1"},
			want: "Internet Information Services 7.5 on Windows Server 2008 R2 for x64-based Systems Service Pack 1",
		},
		{
			name: "Microsoft Windows Messenger prefix stripped",
			args: args{s: "Microsoft Windows Messenger 4.7 on Microsoft Windows XP Service Pack 2"},
			want: "Windows Messenger 4.7 on Microsoft Windows XP Service Pack 2",
		},
		{
			name: "Microsoft Windows Media Player prefix stripped",
			args: args{s: "Microsoft Windows Media Player for Windows XP"},
			want: "Windows Media Player for Windows XP",
		},
		{
			name: "Microsoft Azure Kubernetes Service canonicalized",
			args: args{s: "Microsoft Azure Kubernetes Service"},
			want: "Azure Kubernetes Service",
		},
		{
			name: "Microsoft Azure Functions canonicalized",
			args: args{s: "Microsoft Azure Functions"},
			want: "Azure Functions",
		},
		{
			name: "Microsoft Windows 2000 Advanced Server canonicalized",
			args: args{s: "Microsoft Windows 2000 Advanced Server"},
			want: "Windows 2000 Advanced Server",
		},
		{
			name: "Microsoft Windows NT 4.0 Server canonicalized",
			args: args{s: "Microsoft Windows NT 4.0 Server"},
			want: "Windows NT 4.0 Server",
		},
		{
			name: "Microsoft Windows 2000 Datacenter Server canonicalized",
			args: args{s: "Microsoft Windows 2000 Datacenter Server"},
			want: "Windows 2000 Datacenter Server",
		},
		{
			name: "Microsoft Windows 2000 Server canonicalized",
			args: args{s: "Microsoft Windows 2000 Server"},
			want: "Windows 2000 Server",
		},
		{
			name: "Microsoft SQL Server 2000 SP4 canonicalized",
			args: args{s: "Microsoft SQL Server 2000 Service Pack 4"},
			want: "SQL Server 2000 Service Pack 4",
		},
		{
			name: "Microsoft SQL Server 2000 Reporting Services SP2 canonicalized",
			args: args{s: "Microsoft SQL Server 2000 Reporting Services Service Pack 2"},
			want: "SQL Server 2000 Reporting Services Service Pack 2",
		},
		{
			name: "Outlook for iOS canonicalized",
			args: args{s: "Outlook for iOS"},
			want: "Microsoft Outlook for iOS",
		},
		{
			name: "Service Fabric canonicalized",
			args: args{s: "Service Fabric"},
			want: "Azure Service Fabric",
		},
		{
			name: "Dynamics 365 Business Central 2019 Spring Update canonicalized",
			args: args{s: "Dynamics 365 Business Central 2019 Spring Update"},
			want: "Dynamics 365 Business Central Spring 2019 Update",
		},
		{
			name: "Windows 11 for ARM64-based Systems canonicalized",
			args: args{s: "Windows 11 for ARM64-based Systems"},
			want: "Windows 11 Version 21H2 for ARM64-based Systems",
		},
		{
			name: "Defender for Endpoint Azure Edition canonicalized",
			args: args{s: "Microsoft Defender for Endpoint for Windows on Windows Server 2022 Datacenter: Azure Edition"},
			want: "Microsoft Defender for Endpoint for Windows on Windows Server 2022",
		},
		{
			name: "SCOM 2019 canonicalized",
			args: args{s: "System Center Operations Manager (SCOM) 2019"},
			want: "System Center Operations Manager 2019",
		},
		{
			name: "SCOM 2022 canonicalized",
			args: args{s: "System Center Operations Manager (SCOM) 2022"},
			want: "System Center Operations Manager 2022",
		},
		{
			name: "Teams for Mac Classic Edition canonicalized",
			args: args{s: "Microsoft Teams for Mac, Classic Edition"},
			want: "Microsoft Teams for Mac",
		},
		{
			name: "Teams for Mac New Edition canonicalized",
			args: args{s: "Microsoft Teams for Mac, New Edition"},
			want: "Microsoft Teams for Mac",
		},
		{
			name: "Windows 11 Version 25H2 for ARM systems typo canonicalized",
			args: args{s: "Windows 11 Version 25H2 for ARM systems"},
			want: "Windows 11 Version 25H2 for ARM64-based Systems",
		},
		{
			name: "Windows Defender Antimalware Platform canonicalized to Microsoft branding",
			args: args{s: "Windows Defender Antimalware Platform"},
			want: "Microsoft Defender Antimalware Platform",
		},
		{
			name: "Azure File Sync v18 canonicalized",
			args: args{s: "Azure File Sync v18"},
			want: "Azure File Sync v18.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeProductName(tt.args.s); got != tt.want {
				t.Errorf("NormalizeProductName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveSupersedes(t *testing.T) {
	tests := []struct {
		name string
		kbs  []microsoftkbTypes.KB
		want []microsoftkbTypes.KB
	}{
		{
			name: "basic KB-level: B superseded by A → A supersedes B",
			kbs: []microsoftkbTypes.KB{
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
				{KBID: "1"},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2"}}},
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
			},
		},
		{
			name: "chain: C→B→A → B.Supersedes=[C], A.Supersedes=[B]",
			kbs: []microsoftkbTypes.KB{
				{KBID: "3", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "2"}}},
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
				{KBID: "1"},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2"}}},
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}, Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "3"}}},
				{KBID: "3", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "2"}}},
			},
		},
		{
			name: "fan-in: B→A and C→A → A.Supersedes=[B,C]",
			kbs: []microsoftkbTypes.KB{
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
				{KBID: "3", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
				{KBID: "1"},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2"}, {KBID: "3"}}},
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
				{KBID: "3", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
			},
		},
		{
			name: "superseding KB absent: no Supersedes added, no panic",
			kbs: []microsoftkbTypes.KB{
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "99"}}},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "99"}}},
			},
		},
		{
			name: "self-supersession ignored",
			kbs: []microsoftkbTypes.KB{
				{KBID: "1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}}},
			},
		},
		{
			name: "empty SupersededBy KBID ignored",
			kbs: []microsoftkbTypes.KB{
				{KBID: "1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: ""}}},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: ""}}},
			},
		},
		{
			name: "KB-level deduplication: duplicate SupersededBy entry adds Supersedes only once",
			kbs: []microsoftkbTypes.KB{
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}, {KBID: "1"}}},
				{KBID: "1"},
			},
			want: []microsoftkbTypes.KB{
				{KBID: "1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2"}}},
				{KBID: "2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1"}, {KBID: "1"}}},
			},
		},
		{
			name: "basic update-level: KB2/U2 superseded by KB1/U1 → KB1/U1.Supersedes=[KB2/U2]",
			kbs: []microsoftkbTypes.KB{
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U1"}}},
					},
				},
				{
					KBID:    "1",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
			},
			want: []microsoftkbTypes.KB{
				{
					KBID: "1",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2", UpdateID: "U2"}}},
					},
				},
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U1"}}},
					},
				},
			},
		},
		{
			name: "update self-supersession ignored",
			kbs: []microsoftkbTypes.KB{
				{
					KBID: "1",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U2"}}},
					},
				},
			},
			want: []microsoftkbTypes.KB{
				{
					KBID: "1",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U1", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U2"}}},
					},
				},
			},
		},
		{
			name: "empty UpdateID in SupersededBy skips update-level",
			kbs: []microsoftkbTypes.KB{
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: ""}}},
					},
				},
				{
					KBID:    "1",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
			},
			want: []microsoftkbTypes.KB{
				{
					KBID:    "1",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: ""}}},
					},
				},
			},
		},
		{
			name: "update-level deduplication: duplicate SupersededBy entry adds Supersedes only once",
			kbs: []microsoftkbTypes.KB{
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{
							{KBID: "1", UpdateID: "U1"},
							{KBID: "1", UpdateID: "U1"},
						}},
					},
				},
				{
					KBID:    "1",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
			},
			want: []microsoftkbTypes.KB{
				{
					KBID: "1",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2", UpdateID: "U2"}}},
					},
				},
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{
							{KBID: "1", UpdateID: "U1"},
							{KBID: "1", UpdateID: "U1"},
						}},
					},
				},
			},
		},
		{
			name: "update-level cross-KB: same UpdateID in two KBs only the matching KBID gets Supersedes",
			kbs: []microsoftkbTypes.KB{
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U1"}}},
					},
				},
				// KB1 has U1 — should receive Supersedes.
				{
					KBID:    "1",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
				// KB3 also has U1 — must NOT receive Supersedes because SupersededBy.KBID is "1", not "3".
				{
					KBID:    "3",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
			},
			want: []microsoftkbTypes.KB{
				{
					KBID: "1",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U1", Supersedes: []microsoftkbSupersedesTypes.Supersedes{{KBID: "2", UpdateID: "U2"}}},
					},
				},
				{
					KBID: "2",
					Updates: []microsoftkbUpdateTypes.Update{
						{UpdateID: "U2", SupersededBy: []microsoftkbSupersededByTypes.SupersededBy{{KBID: "1", UpdateID: "U1"}}},
					},
				},
				// KB3/U1 must have no Supersedes.
				{
					KBID:    "3",
					Updates: []microsoftkbUpdateTypes.Update{{UpdateID: "U1"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DeriveSupersedes(tt.kbs)
			for i := range tt.kbs {
				tt.kbs[i].Sort()
			}
			slices.SortFunc(tt.kbs, microsoftkbTypes.Compare)
			for i := range tt.want {
				tt.want[i].Sort()
			}
			slices.SortFunc(tt.want, microsoftkbTypes.Compare)
			if diff := cmp.Diff(tt.want, tt.kbs); diff != "" {
				t.Errorf("DeriveSupersedes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
