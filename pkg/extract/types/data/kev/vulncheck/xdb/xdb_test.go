package xdb_test

import (
	"testing"
	"time"

	xdbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/xdb"
)

func TestCompare(t *testing.T) {
	type args struct {
		x xdbTypes.XDB
		y xdbTypes.XDB
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: xdbTypes.XDB{
					XDBID:       "abc",
					XDBURL:      "https://example.com/abc",
					DateAdded:   time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
					ExploitType: "initial_access",
					CloneSSHURL: "git@example.com:abc.git",
				},
				y: xdbTypes.XDB{
					XDBID:       "abc",
					XDBURL:      "https://example.com/abc",
					DateAdded:   time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
					ExploitType: "initial_access",
					CloneSSHURL: "git@example.com:abc.git",
				},
			},
			want: 0,
		},
		{
			name: "x:xdbId < y:xdbId",
			args: args{
				x: xdbTypes.XDB{XDBID: "aaa"},
				y: xdbTypes.XDB{XDBID: "bbb"},
			},
			want: -1,
		},
		{
			name: "x:dateAdded > y:dateAdded",
			args: args{
				x: xdbTypes.XDB{
					XDBID:     "abc",
					DateAdded: time.Date(2023, time.June, 1, 0, 0, 0, 0, time.UTC),
				},
				y: xdbTypes.XDB{
					XDBID:     "abc",
					DateAdded: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xdbTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
