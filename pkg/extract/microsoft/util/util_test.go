package util

import "testing"

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
