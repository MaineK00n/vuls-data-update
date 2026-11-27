package repository_test

import (
	"testing"

	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
)

func TestCompare(t *testing.T) {
	type args struct {
		x repositoryTypes.Repository
		y repositoryTypes.Repository
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev", Commit: "9e2456a1c61f4ed7a5706bbffaf89ffce20b50eb", Builds: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"}},
				y: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev", Commit: "9e2456a1c61f4ed7a5706bbffaf89ffce20b50eb", Builds: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"}},
			},
			want: 0,
		},
		{
			name: "x:url < y:url",
			args: args{
				x: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev", Commit: "9e2456a1c61f4ed7a5706bbffaf89ffce20b50eb"},
				y: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-microsoft-bulletin", Commit: "3dd51f6ac89db13efedf13fadd1b7f99b174bc5d"},
			},
			want: -1,
		},
		{
			name: "x:commit > y:commit",
			args: args{
				x: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev", Commit: "9e2456a1c61f4ed7a5706bbffaf89ffce20b50eb"},
				y: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev", Commit: "3dd51f6ac89db13efedf13fadd1b7f99b174bc5d"},
			},
			want: +1,
		},
		{
			name: "x:builds < y:builds",
			args: args{
				x: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Builds: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"}},
				y: repositoryTypes.Repository{URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Builds: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb", "filter-vuls-data-extracted-redhat v0.0.0-20261118010337-fe489607c702"}},
			},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := repositoryTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
