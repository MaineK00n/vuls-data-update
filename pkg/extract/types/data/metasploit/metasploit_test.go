package metasploit_test

import (
	"testing"
	"time"

	metasploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/metasploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

func TestMetasploit_Sort(t *testing.T) {
	type fields struct {
		Type        string
		Name        string
		FullName    string
		Description string
		Rank        int
		Published   *time.Time
		Modified    *time.Time
		References  []referenceTypes.Reference
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &metasploitTypes.Metasploit{
				Type:        tt.fields.Type,
				Name:        tt.fields.Name,
				FullName:    tt.fields.FullName,
				Description: tt.fields.Description,
				Rank:        tt.fields.Rank,
				Published:   tt.fields.Published,
				Modified:    tt.fields.Modified,
				References:  tt.fields.References,
			}
			m.Sort()
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
