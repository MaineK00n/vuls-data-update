package v2_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/vex/v2"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	type args struct {
		vex            string
		repository2cpe string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			// The 2019 fixture is CVE-2019-14821 cut down to the rhel-7.8.els
			// products, taken from the feed after CSAF Generator 3.3.1: it
			// carries the "upstream" purl qualifier and the "<source>/" binary
			// product_id prefix, so kernel.src ("Affected") and kernel-alt.src
			// ("Will not fix") keep their own fix state for the kernel,
			// kernel-debug, perf and python-perf binaries they both build.
			//
			// The 2026 CVE-2026-10051 and CVE-2026-68494 fixtures are cut down
			// to their Satellite 6.16 and RHEL products: they pair the
			// bare-module rpmmod SRPMs parseRPMPurl skips with well-formed
			// modular SRPMs that must survive.
			name: "happy",
			args: args{
				vex:            "./testdata/fixtures/vex",
				repository2cpe: "./testdata/fixtures/repository2cpe",
			},
		},
		{
			// A bare-module rpmmod ("rhel10") is tolerated only for the
			// vetted CVE-2026-7323 flatpak SRPMs; the same value in any other
			// advisory must fail loudly.
			name: "bare-module rpmmod outside CVE-2026-7323 errors",
			args: args{
				vex:            "./testdata/fixtures/vex_rpmmod_error",
				repository2cpe: "./testdata/fixtures/repository2cpe",
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := v2.Extract(utiltest.QueryUnescapeFileTree(t, tt.args.vex), tt.args.repository2cpe, v2.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}
