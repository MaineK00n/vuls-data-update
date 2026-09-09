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
			// The 2025 fixture is CVE-2025-40190 cut down to rhel-8.10.z, whose
			// only CPE is cpe:/a:redhat:rhel_e6s:8.10 — a RHEL release
			// majorFromCPE used to read as no RHEL at all, dropping every
			// package under it. The 2016 fixture is CVE-2016-8620 cut down to
			// the two Software Collections products: the bare RHSCL 3 CPE must
			// yield no major (RHSCL 3 ships for RHEL 6 and 7, it is not RHEL 3)
			// while the ::el7 form of the same release still resolves.
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
