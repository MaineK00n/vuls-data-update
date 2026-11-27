package linux_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/oracle/linux"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		golden   string
		hasError bool
	}{
		{
			name:   "happy",
			args:   "./testdata/fixtures/happy",
			golden: "./testdata/golden/happy",
		},
		{
			name:   "modularitylabel",
			args:   "./testdata/fixtures/modularitylabel",
			golden: "./testdata/golden/modularitylabel",
		},
		// Based on "modularitylabel" case, the regexp pattern of module stream is altered and others are identical
		{
			name:   "modularitylabel-stream-reversed",
			args:   "./testdata/fixtures/modularitylabel-stream-reversed",
			golden: "./testdata/golden/modularitylabel-stream-reversed",
		},
		{
			name:   "majormixed",
			args:   "./testdata/fixtures/majormixed",
			golden: "./testdata/golden/majormixed",
		},
		// Synthetic UEK advisories (IDs and CVEs other than CVE-2024-53103 are made up):
		//   ELSA-2024-90010 R4 4.1.12 (OL7), ELSA-2024-90011 R5 4.14.35 (OL7, with perf),
		//   ELSA-2024-90012 R6 5.4.17 (OL7 with kernel-uek-container and perf, OL8),
		//   ELSA-2025-90001 R7 5.15.0 (OL8 x86_64 and aarch64, OL9 x86_64, with bpftool;
		//     shares CVE-2024-0002 with ELSA-2024-90012),
		//   ELSA-2025-90002 and ELSA-2025-90003 R8 6.12.0 (OL9, OL10 / OL9),
		//   ELSA-2025-90020 RHCK (OL8 x86_64, with bpftool)
		{
			name:   "uek",
			args:   "./testdata/fixtures/uek",
			golden: "./testdata/golden/uek",
		},
		// Based on ELSA-2024-90010 of the "uek" case, without the architecture test
		{
			name:     "uek-noarch",
			args:     "./testdata/fixtures/uek-noarch",
			hasError: true,
		},
		// Based on ELSA-2024-90011 of the "uek" case, with perf fixed in another UEK series
		{
			name:     "uek-mixedseries",
			args:     "./testdata/fixtures/uek-mixedseries",
			hasError: true,
		},
		// Based on ELSA-2024-90010 of the "uek" case, defined twice under different OVAL IDs
		{
			name:     "uek-duplicate",
			args:     "./testdata/fixtures/uek-duplicate",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			fixturePath, err := utiltest.QueryUnescapeFileTree(t.TempDir(), tt.args)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			err = linux.Extract(fixturePath, linux.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(tt.golden, dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
