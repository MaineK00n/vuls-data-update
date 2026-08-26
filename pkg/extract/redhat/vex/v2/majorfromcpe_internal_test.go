package v2

import (
	"testing"
)

func TestMajorFromCPE(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			name: "a base release versions itself by its RHEL version",
			arg:  "cpe:/o:redhat:enterprise_linux:9",
			want: "9",
		},
		{
			name: "RHEL 2.1 is the one release with a non-integer major",
			arg:  "cpe:/o:redhat:enterprise_linux:2.1",
			want: "2.1",
		},
		{
			name: "a channel suffix beats the product version",
			arg:  "cpe:/a:redhat:rhel_dotnet:6.0::el7",
			want: "7",
		},
		{
			name: "e6s is RHEL 8.10, the only CPE rhel-8.10.z ever gets",
			arg:  "cpe:/a:redhat:rhel_e6s:8.10",
			want: "8",
		},
		{
			name: "extended EUS keeps the RHEL version, behind a channel that is not el<N>",
			arg:  "cpe:/a:redhat:rhel_eus_long_life:8.4::appstream",
			want: "8",
		},
		{
			name: "the ELS variant of an extras channel is still RHEL",
			arg:  "cpe:/a:redhat:rhel_extras_rt_els:7",
			want: "7",
		},
		{
			name: "virtualization channels carry a client/server suffix, not el<N>",
			arg:  "cpe:/a:redhat:rhel_virtualization:5::server",
			want: "5",
		},
		{
			name: "a Satellite client CPE is versioned by Satellite, not RHEL",
			arg:  "cpe:/a:redhat:rhel_satellite_client:6",
			want: "",
		},
		{
			name: "a product outside RHEL",
			arg:  "cpe:/a:redhat:openshift:4",
			want: "",
		},
		{
			name: "another vendor",
			arg:  "cpe:/o:centos:centos:7",
			want: "",
		},
		{
			name: "unparsable",
			arg:  "not a cpe",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := majorFromCPE(tt.arg); got != tt.want {
				t.Errorf("majorFromCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}
