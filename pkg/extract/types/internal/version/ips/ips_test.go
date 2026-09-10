package ips_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/version/ips"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		wantErr bool
	}{
		{name: "release only", v: "1.8.0.471"},
		{name: "one element", v: "3"},
		{name: "release and build", v: "0.5.11,5.11"},
		{name: "release and branch", v: "11.4-11.4.94"},
		{name: "release and timestamp", v: "0.5.11:20161018T000000Z"},
		{name: "release, branch and timestamp", v: "11.4-11.4.0.0.1.15.0:20180817T004203Z"},
		{name: "full", v: "0.5.11,5.11-0.175.3.13.0.4.0:20160929T175502Z"},
		{name: "release and timestamp, no branch", v: "1.8.0.181.12:20180711T215531Z"},
		{name: "zero element", v: "0.5.11-0.175.0.0.0.2.0"},
		{name: "surrounding whitespace", v: " 11.4 "},
		{name: "empty", v: "", wantErr: true},
		{name: "prose", v: "prior to 11.4", wantErr: true},
		{name: "no release", v: ",5.11-0.175", wantErr: true},
		{name: "no release, branch only", v: "-0.175", wantErr: true},
		{name: "empty build", v: "1.0,", wantErr: true},
		{name: "empty branch", v: "1.0-", wantErr: true},
		{name: "empty branch before timestamp", v: "1.0-:20180817T004203Z", wantErr: true},
		{name: "empty timestamp", v: "1.0:", wantErr: true},
		{name: "trailing dot", v: "11.4.", wantErr: true},
		{name: "leading dot", v: ".11.4", wantErr: true},
		{name: "double dot", v: "11..4", wantErr: true},
		{name: "non numeric", v: "11.4a", wantErr: true},
		{name: "negative element", v: "11.-4", wantErr: true},
		{name: "signed element", v: "+11.4", wantErr: true},
		{name: "zero padded element", v: "11.04", wantErr: true},
		{name: "zero padded zero", v: "11.00", wantErr: true},
		{name: "lone zero", v: "0.5.11", wantErr: false},
		{name: "zero padded branch element", v: "11.4-11.04", wantErr: true},
		{name: "timestamp date only", v: "1.0:20161018", wantErr: true},
		{name: "timestamp without Z", v: "1.0:20161018T000000", wantErr: true},
		{name: "timestamp impossible date", v: "1.0:20161340T000000Z", wantErr: true},
		{name: "timestamp with offset", v: "1.0:20161018T000000+0900", wantErr: true},
		{name: "semver", v: "1.0.0-beta.1", wantErr: true},
		{name: "rpm", v: "1.0.2k-8.el7", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ips.NewVersion(tt.v); (err != nil) != tt.wantErr {
				t.Errorf("NewVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVersion_Compare(t *testing.T) {
	tests := []struct {
		name string
		v    string
		w    string
		want int
	}{
		// release
		{name: "equal release", v: "11.4", w: "11.4", want: 0},
		{name: "release element", v: "11.3", w: "11.4", want: -1},
		{name: "release element is numeric, not lexical", v: "11.4.9", w: "11.4.10", want: -1},
		{name: "shorter release is a prefix and sorts first", v: "11.4", w: "11.4.0", want: -1},
		{name: "release decides before branch", v: "11.3-11.3.99", w: "11.4-11.4.1", want: -1},
		{name: "release decides before timestamp", v: "0.5.11:20261231T235959Z", w: "0.5.12:20150101T000000Z", want: -1},
		// build_release is not part of the order
		{name: "build release ignored", v: "0.5.11,5.11", w: "0.5.11,5.12", want: 0},
		{name: "build release ignored, one side only", v: "0.5.11,5.11-0.175.3.1.0.3.0", w: "0.5.11-0.175.3.1.0.3.0", want: 0},
		// branch
		{name: "branch element", v: "11.4-11.4.93.0.1.110.0", w: "11.4-11.4.94.0.1.113.1", want: -1},
		{name: "branch prefix sorts first", v: "11.4-11.4.94", w: "11.4-11.4.94.0.1.113.1", want: -1},
		{name: "same branch prefix and beyond", v: "11.4-11.4.94.0.1.113.1", w: "11.4-11.4.94.0.1.113.1", want: 0},
		{name: "branch decides before timestamp", v: "11.4-11.4.2:20261231T235959Z", w: "11.4-11.4.3:20150101T000000Z", want: -1},
		{name: "branch element is numeric, not lexical", v: "0.5.11-0.175.3.9.0.3.0", w: "0.5.11-0.175.3.13.0.4.0", want: -1},
		// timestamp
		{name: "timestamp", v: "0.5.11-0.175.3.13.0.4.0:20160929T175502Z", w: "0.5.11-0.175.3.13.0.4.0:20161018T000000Z", want: -1},
		{name: "timestamp equal", v: "11.4:20180817T004203Z", w: "11.4:20180817T004203Z", want: 0},
		// don't care: a component missing on either side is skipped
		{name: "branch missing on one side", v: "0.5.11:20161018T000000Z", w: "0.5.11,5.11-0.175.3.13.0.4.0:20160929T175502Z", want: 1},
		{name: "branch missing, timestamp decides the other way", v: "0.5.11:20161018T000000Z", w: "0.5.11,5.11-0.175.3.14.0.6.0:20161118T000000Z", want: -1},
		{name: "timestamp missing on one side", v: "11.4-11.4.94", w: "11.4-11.4.93.0.1.110.0:20260101T000000Z", want: 1},
		{name: "branch and timestamp missing on one side", v: "1.8.0.471", w: "1.8.0.181.12:20180711T215531Z", want: 1},
		{name: "release only both sides", v: "1.8.0.471", w: "1.8.0.501.8", want: -1},
		{name: "only the release is shared and it is equal", v: "11.4", w: "11.4-11.4.0.0.1.15.0:20180817T004203Z", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ips.NewVersion(tt.v)
			if err != nil {
				t.Fatalf("NewVersion(%q) error = %v", tt.v, err)
			}
			w, err := ips.NewVersion(tt.w)
			if err != nil {
				t.Fatalf("NewVersion(%q) error = %v", tt.w, err)
			}
			if got := v.Compare(w); got != tt.want {
				t.Errorf("Compare() = %d, want %d", got, tt.want)
			}
		})
	}
}
