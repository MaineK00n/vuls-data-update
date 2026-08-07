package servicing_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/servicing"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixtures are articles as fetched, chosen for what decides a chain.
//
// dotnetframework carries no build numbers, so its three are ordered by the
// date in the title -- which two of them file under a folder month that is not
// their release month, the shape the path must not be trusted for.
//
// os/windows-11 carries them, and holds three lines at once. 26200 and 26100
// run together through four revisions; 28000 is a version of its own and links
// to neither, though all four sit in one series and two share a month.
//
// os/windows-server is there for the build number that is not unique: Windows
// Server 2025 is 26100 as Windows 11 24H2 is, with its own KB at a revision
// Windows 11 also ships. It belongs to neither of the other chains.
//
// The last two name no KB. A series listing carries its hub page and its end of
// servicing statement alongside the updates, and neither is one.
func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures/happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := servicing.Extract(tt.args, servicing.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
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
