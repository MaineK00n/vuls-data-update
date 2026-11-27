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
			name: "dependency of another program",
			args: args{
				info: &debug.BuildInfo{
					Main: debug.Module{Path: "filter-vuls-data-extracted-redhat", Version: "v0.0.0-20261118010337-fe489607c702"},
					Deps: []*debug.Module{
						{Path: "github.com/hashicorp/go-version", Version: "v1.8.0"},
						{Path: "github.com/MaineK00n/vuls-data-update", Version: "v0.0.0-20260303093643-b8a08531c5a9"},
					},
				},
				ok: true,
			},
			want: "vuls-data-update v0.0.0-20260303093643-b8a08531c5a9",
		},
		{
			name: "dependency replaced by another version",
			args: args{
				info: &debug.BuildInfo{
					Main: debug.Module{Path: "github.com/MaineK00n/vuls2", Version: "(devel)"},
					Deps: []*debug.Module{{
						Path:    "github.com/MaineK00n/vuls-data-update",
						Version: "v0.0.0-20260303093643-b8a08531c5a9",
						Replace: &debug.Module{Path: "github.com/MaineK00n/vuls-data-update", Version: "v0.0.0-20261126020019-9f06544f77cb"},
					}},
				},
				ok: true,
			},
			want: "vuls-data-update v0.0.0-20261126020019-9f06544f77cb",
		},
		{
			name: "dependency replaced by a directory",
			args: args{
				info: &debug.BuildInfo{
					Main: debug.Module{Path: "github.com/MaineK00n/vuls2", Version: "(devel)"},
					Deps: []*debug.Module{{
						Path:    "github.com/MaineK00n/vuls-data-update",
						Version: "v0.0.0-20260303093643-b8a08531c5a9",
						Replace: &debug.Module{Path: "../vuls-data-update", Version: "(devel)"},
					}},
				},
				ok: true,
			},
			want: "vuls-data-update (devel)",
		},
		{
			name: "replacement with no version at all",
			args: args{
				info: &debug.BuildInfo{
					Main: debug.Module{Path: "github.com/MaineK00n/vuls2", Version: "(devel)"},
					Deps: []*debug.Module{{
						Path:    "github.com/MaineK00n/vuls-data-update",
						Version: "v0.0.0-20260303093643-b8a08531c5a9",
						Replace: &debug.Module{Path: "../vuls-data-update"},
					}},
				},
				ok: true,
			},
			want: "vuls-data-update (devel)",
		},
		{
			name: "module not in the build",
			args: args{
				info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/other", Version: "v1.0.0"}},
				ok:   true,
			},
			want: "vuls-data-update (unknown)",
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
