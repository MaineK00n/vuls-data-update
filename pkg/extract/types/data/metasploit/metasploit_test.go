package metasploit_test

import (
	"reflect"
	"testing"

	metasploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/metasploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

func TestMetasploit_Sort(t *testing.T) {
	tests := []struct {
		name  string
		input metasploitTypes.Metasploit
		want  metasploitTypes.Metasploit
	}{
		{
			name: "sorts all slice fields",
			input: metasploitTypes.Metasploit{
				Type:     "exploit",
				Name:     "SMB DOUBLEPULSAR Remote Code Execution",
				FullName: "exploit/windows/smb/smb_doublepulsar_rce",
				Aliases:  []string{"exploit/windows/smb/doublepulsar_rce", "exploit/windows/smb/alias_a"},
				Author:   []string{"zerosum0x0", "Luke Jennings", "Shadow Brokers"},
				Targets:  []string{"Windows x64 (Native Payload)", "Windows x64", "Windows x86"},
				References: []referenceTypes.Reference{
					{Source: "rapid7/metasploit", URL: "https://zerosum0x0.blogspot.com"},
					{Source: "rapid7/metasploit", URL: "https://www.cve.org/CVERecord?id=CVE-2017-0143"},
				},
			},
			want: metasploitTypes.Metasploit{
				Type:     "exploit",
				Name:     "SMB DOUBLEPULSAR Remote Code Execution",
				FullName: "exploit/windows/smb/smb_doublepulsar_rce",
				Aliases:  []string{"exploit/windows/smb/alias_a", "exploit/windows/smb/doublepulsar_rce"},
				Author:   []string{"Luke Jennings", "Shadow Brokers", "zerosum0x0"},
				Targets:  []string{"Windows x64", "Windows x64 (Native Payload)", "Windows x86"},
				References: []referenceTypes.Reference{
					{Source: "rapid7/metasploit", URL: "https://www.cve.org/CVERecord?id=CVE-2017-0143"},
					{Source: "rapid7/metasploit", URL: "https://zerosum0x0.blogspot.com"},
				},
			},
		},
		{
			name:  "empty slices",
			input: metasploitTypes.Metasploit{Type: "auxiliary"},
			want:  metasploitTypes.Metasploit{Type: "auxiliary"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.Sort()
			if !reflect.DeepEqual(tt.input, tt.want) {
				t.Errorf("Sort() result mismatch:\n got  %+v\n want %+v", tt.input, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x metasploitTypes.Metasploit
		y metasploitTypes.Metasploit
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: metasploitTypes.Metasploit{
					Type:     "auxiliary",
					Rank:     300,
					FullName: "/modules/auxiliary/admin/2wire/xslt_password_reset.rb",
				},
				y: metasploitTypes.Metasploit{
					Type:     "auxiliary",
					Rank:     300,
					FullName: "/modules/auxiliary/admin/2wire/xslt_password_reset.rb",
				},
			},
			want: 0,
		},
		{
			name: "x:type < y:type",
			args: args{
				x: metasploitTypes.Metasploit{
					Type: "auxiliary",
				},
				y: metasploitTypes.Metasploit{
					Type: "exploit",
				},
			},
			want: -1,
		},
		{
			name: "x:rank < y:rank",
			args: args{
				x: metasploitTypes.Metasploit{
					Type: "exploit",
					Rank: 500,
				},
				y: metasploitTypes.Metasploit{
					Type: "exploit",
					Rank: 600,
				},
			},
			want: -1,
		},
		{
			name: "x:fullname > y:fullname",
			args: args{
				x: metasploitTypes.Metasploit{
					Type:     "exploit",
					Rank:     600,
					FullName: "exploit/aix/local/invscout_rpm_priv_esc",
				},
				y: metasploitTypes.Metasploit{
					Type:     "exploit",
					Rank:     600,
					FullName: "exploit/aix/local/ibstat_path",
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := metasploitTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
