package version

import (
	"runtime/debug"
	"testing"
)

func TestFormat(t *testing.T) {
	type args struct {
		info *debug.BuildInfo
		ok   bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "pseudo-version",
			args: args{
				info: &debug.BuildInfo{Main: debug.Module{Path: "github.com/MaineK00n/vuls-data-update", Version: "v0.0.0-20261126020019-9f06544f77cb"}},
				ok:   true,
			},
			want: "vuls-data-update v0.0.0-20261126020019-9f06544f77cb",
		},
		{
			name: "dirty tree",
			args: args{
				info: &debug.BuildInfo{Main: debug.Module{Path: "github.com/MaineK00n/vuls-data-update", Version: "v0.0.0-20261126020019-9f06544f77cb+dirty"}},
				ok:   true,
			},
			want: "vuls-data-update v0.0.0-20261126020019-9f06544f77cb+dirty",
		},
		{
			name: "no version recorded",
			args: args{
				info: &debug.BuildInfo{Main: debug.Module{Path: "github.com/MaineK00n/vuls-data-update", Version: "(devel)"}},
				ok:   true,
			},
			want: "vuls-data-update (devel)",
		},
		{
			name: "no build info",
			args: args{},
			want: "vuls-data-update (unknown)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := format(tt.args.info, tt.args.ok); got != tt.want {
				t.Errorf("format() = %q, want %q", got, tt.want)
			}
		})
	}
}
