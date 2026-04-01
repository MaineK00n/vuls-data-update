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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeProductName(tt.args.s); got != tt.want {
				t.Errorf("NormalizeProductName() = %v, want %v", got, tt.want)
			}
		})
	}
}
