package errata_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
)

func TestSRPMName(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string
	}{
		{name: "kernel", args: "kernel-5.14.0-687.59.1.el9_8.src.rpm", want: "kernel"},
		{name: "kernel-rt", args: "kernel-rt-4.18.0-553.5.1.rt7.346.el8_10.src.rpm", want: "kernel-rt"},
		{name: "another source package", args: "linux-firmware-20261101-150.el9_9.src.rpm", want: "linux-firmware"},
		{name: "binary package", args: "kernel-5.14.0-687.59.1.el9_8.x86_64.rpm", want: ""},
		{name: "no release", args: "kernel-5.14.0.src.rpm", want: ""},
		{name: "empty", args: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errata.SRPMName(tt.args); got != tt.want {
				t.Errorf("SRPMName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMinorOf(t *testing.T) {
	tests := []struct {
		name   string
		args   string
		want   int
		wantOK bool
	}{
		{name: "update", args: "687.59.1.el9_8", want: 687, wantOK: true},
		{name: "first build of a minor", args: "553.el8_10", want: 553, wantOK: true},
		{name: "kernel-rt", args: "553.5.1.rt7.346.el8_10", want: 553, wantOK: true},
		{name: "no dot", args: "687", want: 687, wantOK: true},
		{name: "not a number", args: "rc1.el9", wantOK: false},
		{name: "sign", args: "+687.el9", wantOK: false},
		{name: "overflow", args: "99999999999999999999.el9", wantOK: false},
		{name: "empty", args: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := errata.MinorOf(tt.args)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("MinorOf() = (%d, %t), want (%d, %t)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
