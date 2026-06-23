package product_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
)

func TestToCPE(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{name: "FortiOS", want: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "FortiClientWindows", want: "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "  FortiProxy  ", want: "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*", wantOK: true},
		{name: "Nonexistent Product", want: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := product.ToCPE(tt.name)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("ToCPE(%q) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestBakeVersion(t *testing.T) {
	type args struct {
		cpe     string
		version string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "concrete version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", version: "7.4.3"},
			want: "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
		},
		{
			name: "hyphenated version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*", version: "6.1-2-29"},
			want: "cpe:2.3:o:fortinet:fortiswitch:6.1-2-29:*:*:*:*:*:*:*",
		},
		{
			name:    "invalid cpe",
			args:    args{cpe: "not-a-cpe", version: "1.0.0"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := product.BakeVersion(tt.args.cpe, tt.args.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BakeVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("BakeVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
