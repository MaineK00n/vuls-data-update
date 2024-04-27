package metasploit_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/metasploit"
)

func TestCompare(t *testing.T) {
	type args struct {
		x metasploit.Metasploit
		y metasploit.Metasploit
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: metasploit.Metasploit{
					Type:     "auxiliary",
					Rank:     300,
					FullName: "/modules/auxiliary/admin/2wire/xslt_password_reset.rb",
				},
				y: metasploit.Metasploit{
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
				x: metasploit.Metasploit{
					Type: "auxiliary",
				},
				y: metasploit.Metasploit{
					Type: "exploit",
				},
			},
			want: -1,
		},
		{
			name: "x:rank < y:rank",
			args: args{
				x: metasploit.Metasploit{
					Type: "exploit",
					Rank: 500,
				},
				y: metasploit.Metasploit{
					Type: "exploit",
					Rank: 600,
				},
			},
			want: -1,
		},
		{
			name: "x:fullname > y:fullname",
			args: args{
				x: metasploit.Metasploit{
					Type:     "exploit",
					Rank:     600,
					FullName: "exploit/aix/local/invscout_rpm_priv_esc",
				},
				y: metasploit.Metasploit{
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
			if got := metasploit.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
