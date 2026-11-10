package officec2r_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/officec2r"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The happy fixtures are fetched release entries, each trimmed to a few CVEs
// per application, chosen for what decides a range:
//
//   - 2019-01-08: Semi-Annual Channel serving three branches at once (1808,
//     1803, 1708), and the "Office 365 ProPlus" name of the era.
//   - 2019-03-12: an entry stating there are no security updates.
//   - 2020-04-14 / 2020-05-12: the last entry under the "Office 365 ProPlus"
//     name and the first under "Microsoft 365 Apps for Enterprise".
//   - 2021-08-10 / 2021-08-17: CVE-2021-34478 listed again a week later
//     ("Fix was updated for this CVE"); the first listing decides.
//   - 2022-08-09: a Monthly Enterprise Channel build rolled back and released
//     again; the lower revision of the branch is the bound.
//   - 2023-03-14: the page labels build 16130 "Version 2301" on two lines and
//     "Version 2302" on the others; branches are keyed by build.
//   - 2024-12-10: ADV240002, an advisory rather than a CVE.
//   - 2025-04-08 / 2025-04-15: CVE-2025-27751 listed again in a
//     single-channel out-of-band entry; the first listing decides.
//   - 2026-10-13: the volume-licensed bands of Office 2019, LTSC 2021 and
//     LTSC 2024 beside the retail branches of the same families, and Office
//     2019 with no retail line left.
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
			name:     "unknown-channel",
			args:     "./testdata/fixtures/unknown-channel",
			hasError: true,
		},
		{
			name:     "unexpected-build-note",
			args:     "./testdata/fixtures/unexpected-build-note",
			hasError: true,
		},
		{
			name:     "unexpected-item-text",
			args:     "./testdata/fixtures/unexpected-item-text",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := officec2r.Extract(tt.args, officec2r.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join(tt.golden), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
